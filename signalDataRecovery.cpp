// signalDataRecovery.cpp : 定义应用程序的入口点。
//

#include <windows.h>
#include <winioctl.h>

// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

#include <stdio.h>
#include <assert.h>
#include <stdint.h>

// C++ header files
#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include "signalDataRecovery.h"

#define IOCTL_DISK_GET_DRIVE_LAYOUT 0x00070050  // 获取磁盘分区布局

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#pragma pack(push,1)
struct BootSector {
    uint8_t     jump[3];
    char        name[8];
    uint16_t    bytesPerSector;
    uint8_t     sectorsPerCluster;
    uint16_t    reservedSectors;
    uint8_t     unused0[3];
    uint16_t    unused1;
    uint8_t     media;
    uint16_t    unused2;
    uint16_t    sectorsPerTrack;
    uint16_t    headsPerCylinder;
    uint32_t    hiddenSectors;
    uint32_t    unused3;
    uint32_t    unused4;
    uint64_t    totalSectors;
    uint64_t    mftStart;
    uint64_t    mftMirrorStart;
    uint32_t    clustersPerFileRecord;
    uint32_t    clustersPerIndexBlock;
    uint64_t    serialNumber;
    uint32_t    checksum;
    uint8_t     bootloader[426];
    uint16_t    bootSignature;
};

struct FileRecordHeader {
    uint32_t    magic;
    uint16_t    updateSequenceOffset;
    uint16_t    updateSequenceSize;
    uint64_t    logSequence;
    uint16_t    sequenceNumber;
    uint16_t    hardLinkCount;
    uint16_t    firstAttributeOffset;
    uint16_t    inUse : 1;
    uint16_t    isDirectory : 1;
    uint32_t    usedSize;
    uint32_t    allocatedSize;
    uint64_t    fileReference;
    uint16_t    nextAttributeID;
    uint16_t    unused;
    uint32_t    recordNumber;
};

struct AttributeHeader {
    uint32_t    attributeType;
    uint32_t    length;
    uint8_t     nonResident;
    uint8_t     nameLength;
    uint16_t    nameOffset;
    uint16_t    flags;
    uint16_t    attributeID;
};

struct ResidentAttributeHeader : AttributeHeader {
    uint32_t    attributeLength;
    uint16_t    attributeOffset;
    uint8_t     indexed;
    uint8_t     unused;
};

struct FileNameAttributeHeader : ResidentAttributeHeader {
    uint64_t    parentRecordNumber : 48;
    uint64_t    sequenceNumber : 16;
    uint64_t    creationTime;
    uint64_t    modificationTime;
    uint64_t    metadataModificationTime;
    uint64_t    readTime;
    uint64_t    allocatedSize;
    uint64_t    realSize;
    uint32_t    flags;
    uint32_t    repase;
    uint8_t     fileNameLength;
    uint8_t     namespaceType;
    wchar_t     fileName[1];
};

struct NonResidentAttributeHeader : AttributeHeader {
    uint64_t    firstCluster;
    uint64_t    lastCluster;
    uint16_t    dataRunsOffset;
    uint16_t    compressionUnit;
    uint32_t    unused;
    uint64_t    attributeAllocated;
    uint64_t    attributeSize;
    uint64_t    streamDataSize;
};

struct RunHeader {
    uint8_t     lengthFieldBytes : 4;
    uint8_t     offsetFieldBytes : 4;
};
#pragma pack(pop)

struct File {
    uint64_t    parent;
    char* name;
};

File* files;

DWORD bytesAccessed = 0;
HANDLE drive = NULL;

BootSector bootSector;

#define MFT_FILE_SIZE (1024)
uint8_t mftFile[MFT_FILE_SIZE];

#define MFT_FILES_PER_BUFFER (65536)
uint8_t mftBuffer[MFT_FILES_PER_BUFFER * MFT_FILE_SIZE];

char* DuplicateName(wchar_t* name, size_t nameLength) {
    static char* allocationBlock = nullptr;
    static size_t bytesRemaining = 0;

    size_t bytesNeeded = WideCharToMultiByte(CP_UTF8, 0, name, nameLength, NULL, 0, NULL, NULL) + 1;

    if (bytesRemaining < bytesNeeded) {
        allocationBlock = (char*)malloc((bytesRemaining = 16 * 1024 * 1024));
    }

    char* buffer = allocationBlock;
    buffer[bytesNeeded - 1] = 0;
    WideCharToMultiByte(CP_UTF8, 0, name, nameLength, allocationBlock, bytesNeeded, NULL, NULL);

    bytesRemaining -= bytesNeeded;
    allocationBlock += bytesNeeded;

    return buffer;
}

void Read(void* buffer, uint64_t from, uint64_t count) {
    LONG high = from >> 32;
    SetFilePointer(drive, from & 0xFFFFFFFF, &high, FILE_BEGIN);
    ReadFile(drive, buffer, count, &bytesAccessed, NULL);
    assert(bytesAccessed == count);
}

void dump2file(const char* filename, const unsigned char* buffer, const int size)
{
    FILE* hdump = NULL;
    if (NULL == hdump)
        fopen_s(&hdump, filename, "w");
    if (hdump)
    {
        fwrite(buffer, 1, size, hdump);
        fflush(hdump);
        fclose(hdump);
    }
}

int parseMFT() {

    drive = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == drive)
    {
        DWORD err = GetLastError();
        printf("last error: %u", err);
    }

    Read(&bootSector, 0, 512);

    dump2file("bootsector.hex", (const unsigned char*)&bootSector, 512);

    uint64_t bytesPerCluster = bootSector.bytesPerSector * bootSector.sectorsPerCluster;

    Read(mftFile, bootSector.mftStart * bytesPerCluster, MFT_FILE_SIZE);

    dump2file("mft.hex", (const unsigned char*)mftFile, MFT_FILE_SIZE);

    FileRecordHeader* fileRecord = (FileRecordHeader*)mftFile;
    AttributeHeader* attribute = (AttributeHeader*)(mftFile + fileRecord->firstAttributeOffset);

    NonResidentAttributeHeader* dataAttribute = nullptr;
    uint64_t approximateRecordCount = 0;
    assert(fileRecord->magic == 0x454C4946);

    while (true) {
        if (attribute->attributeType == 0x80) {
            dataAttribute = (NonResidentAttributeHeader*)attribute;
        }
        else if (attribute->attributeType == 0xB0) {
            approximateRecordCount = ((NonResidentAttributeHeader*)attribute)->attributeSize * 8;
        }
        else if (attribute->attributeType == 0xFFFFFFFF) {
            break;
        }

        attribute = (AttributeHeader*)((uint8_t*)attribute + attribute->length);
    }

    assert(dataAttribute);
    RunHeader* dataRun = (RunHeader*)((uint8_t*)dataAttribute + dataAttribute->dataRunsOffset);
    uint64_t clusterNumber = 0, recordsProcessed = 0;

    FILE* hfiles = NULL;
    char filename[1024];
    fopen_s(&hfiles, "allfiles.txt", "w");
    while (((uint8_t*)dataRun - (uint8_t*)dataAttribute) < dataAttribute->length && dataRun->lengthFieldBytes) {
        uint64_t length = 0, offset = 0;

        for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
            uint8_t c = ((uint8_t*)dataRun)[1 + i];
            printf("%d %c\n", c, c);
            length |= (uint64_t)(c) << (i * 8);
        }

        for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
            uint8_t c = ((uint8_t*)dataRun)[1 + dataRun->lengthFieldBytes + i];
            offset |= (uint64_t)(c) << (i * 8);
        }

        if (offset & ((uint64_t)1 << (dataRun->offsetFieldBytes * 8 - 1))) {
            for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
                offset |= (uint64_t)0xFF << (i * 8);
            }
        }

        clusterNumber += offset;
        dataRun = (RunHeader*)((uint8_t*)dataRun + 1 + dataRun->lengthFieldBytes + dataRun->offsetFieldBytes);

        uint64_t filesRemaining = length * bytesPerCluster / MFT_FILE_SIZE;
        uint64_t remained = length * bytesPerCluster % MFT_FILE_SIZE;
        uint64_t positionInBlock = 0;

        while (filesRemaining) {
            fprintf(stderr, "%d%% ", (int)(recordsProcessed * 100 / approximateRecordCount));

            uint64_t filesToLoad = MFT_FILES_PER_BUFFER;
            if (filesRemaining < MFT_FILES_PER_BUFFER) filesToLoad = filesRemaining;
            Read(&mftBuffer, clusterNumber * bytesPerCluster + positionInBlock, filesToLoad * MFT_FILE_SIZE);
            positionInBlock += filesToLoad * MFT_FILE_SIZE;
            filesRemaining -= filesToLoad;

            for (int i = 0; i < filesToLoad; i++) {
                // Even on an SSD, processing the file records takes only a fraction of the time to read the data,
                // so there's not much point in multithreading this.

                FileRecordHeader* fileRecord = (FileRecordHeader*)(mftBuffer + MFT_FILE_SIZE * i);
                recordsProcessed++;
                #if (1)
                    if (/*38912 == filesRemaining*/ /*clusterNumber == 786432 && positionInBlock == 67108864 &&*/ 33844 == fileRecord->recordNumber/* && 63949 == recordsProcessed */ )
                        dump2file("testfile-deleted.mft", (const uint8_t*)(mftBuffer + MFT_FILE_SIZE * i), MFT_FILE_SIZE);
                #endif
                if (!fileRecord->inUse)
                {
                    continue;
                }
                AttributeHeader* attribute = (AttributeHeader*)((uint8_t*)fileRecord + fileRecord->firstAttributeOffset);
                //assert(fileRecord->magic == 0x454C4946);

                while ((uint8_t*)attribute - (uint8_t*)fileRecord < MFT_FILE_SIZE) {

                    if (attribute->attributeType == 0x30) {

                        FileNameAttributeHeader* fileNameAttribute = (FileNameAttributeHeader*)attribute;
                        if (fileNameAttribute->namespaceType != 2 && !fileNameAttribute->nonResident) {
                            File file = {};
                            //file.parent = fileNameAttribute->parentRecordNumber;
                            file.name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);
                            //printf("file: %s\n", file.name);
                            sprintf_s(filename, 1024, "%s, isDir: %d, flag: %d, nameSpace: %d\n", file.name, fileRecord->isDirectory, fileNameAttribute->flags, fileNameAttribute->namespaceType);
                            fwrite(filename, 1, strlen(filename), hfiles);
                            fflush(hfiles);

                            if (strcmp(file.name, "asdfasdfsadfsad.txt") == 0)
                            {
                                dump2file("testfile.mft", (const uint8_t*)(mftBuffer + MFT_FILE_SIZE * i), MFT_FILE_SIZE);
                            }
                            //uint64_t oldLength = arrlenu(files);

                            //if (fileRecord->recordNumber >= oldLength) {
                            //    arrsetlen(files, fileRecord->recordNumber + 1);
                            //    memset(files + oldLength, 0, sizeof(File) * (fileRecord->recordNumber - oldLength));
                            //}

                            //files[fileRecord->recordNumber] = file;
                        }
                    }
                    else if (attribute->attributeType == 0xFFFFFFFF) {
                        break;
                    }

                    attribute = (AttributeHeader*)((uint8_t*)attribute + attribute->length);
                }
            }
        }
    }
    fclose(hfiles);
    //fprintf(stderr, "\nFound %lld files.\n", arrlen(files));
    int64_t num = arrlen(files);
    printf("\nFound %lld files.\n", num);

    return 0;
}


// 读取磁盘的分区布局
void ReadPartitionTable(const std::string& diskPath) 
{

    HANDLE hDisk = CreateFileA(diskPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        std::cerr << "无法打开磁盘设备: " << diskPath << std::endl;
        return;
    }

    DWORD bytesReturned = 0;
    unsigned char buff[1024] = {0};

    BOOL result = DeviceIoControl(
        hDisk,
        IOCTL_DISK_GET_DRIVE_LAYOUT,
        NULL,
        0,
        buff,
        sizeof(buff),
        &bytesReturned,
        NULL
    );

    if (result) 
    {
        std::cout << "分区布局信息：\n";
        DRIVE_LAYOUT_INFORMATION_EX* driveLayout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(buff);
        for (DWORD i = 0; i < driveLayout->PartitionCount; ++i) 
        {
            PARTITION_INFORMATION_EX partition = driveLayout->PartitionEntry[i];
            std::cout << "分区 " << i + 1 << ":\n";
            std::cout << "  分区类型: " << partition.PartitionStyle << "\n";
            std::cout << "  起始LBA: " << partition.StartingOffset.QuadPart << "\n";
            std::cout << "  大小: " << partition.PartitionLength.QuadPart << "\n";
        }
    }
    else 
    {
        DWORD err = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == err)
        {
            unsigned char buffer[2048];
            result = DeviceIoControl(
                hDisk,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                NULL,
                0,
                buffer,
                sizeof(buffer),
                &bytesReturned,
                NULL
            );

            if (result) {
                // 解析返回的分区布局信息
                DRIVE_LAYOUT_INFORMATION_EX* extendedLayout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(buffer);
                std::cout << "分区布局信息：\n";
                for (DWORD i = 0; i < extendedLayout->PartitionCount; ++i) {
                    PARTITION_INFORMATION_EX partition = extendedLayout->PartitionEntry[i];
                    std::cout << "分区 " << i + 1 << ":\n";
                    std::cout << "  分区类型: " << partition.PartitionStyle << "\n";
                    std::cout << "  起始LBA: " << partition.StartingOffset.QuadPart << "\n";
                    std::cout << "  大小: " << partition.PartitionLength.QuadPart << "\n";
                }
            }
            else 
            {
                std::cerr << "获取分区布局失败，错误码：" << GetLastError() << std::endl;
            }
        }
    }

    CloseHandle(hDisk);
}

// 恢复分区表条目的简单逻辑
void RestorePartitionEntry(HANDLE hDisk, PARTITION_INFORMATION_EX& partition) 
{
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDisk,
        IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
        &partition,
        sizeof(partition),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) 
    {
        std::cout << "分区恢复成功！" << std::endl;
    }
    else 
    {
        std::cerr << "恢复分区失败！" << std::endl;
    }
}

void CheckAndFixFileSystem(const std::string& driveLetter) {
    std::string command = "chkdsk " + driveLetter + " /f";
    system(command.c_str());  // 执行 chkdsk 命令
}

int main() 
{

    // 物理磁盘路径，Windows 中通常是 \\\\.\\PhysicalDriveX
    std::string diskPath = "\\\\.\\PhysicalDrive0"; // 这里以磁盘 0 为例
    ReadPartitionTable(diskPath);

    //parseMFT();
    return 0;
}
