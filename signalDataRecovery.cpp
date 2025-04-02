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

    HANDLE hDisk = CreateFileA(diskPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        std::cerr << "无法打开磁盘，错误代码: " << GetLastError() << std::endl;
        return;
    }

    // 准备缓冲区接收布局信息
    BYTE layoutBuffer[1024];
    DWORD bytesReturned;
    if (!DeviceIoControl(hDisk,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL,
        0,
        layoutBuffer,
        sizeof(layoutBuffer),
        &bytesReturned,
        NULL)) {
        std::cerr << "获取磁盘布局失败，错误代码: " << GetLastError() << std::endl;
        CloseHandle(hDisk);
        return;
    }

    // 解析布局信息
    DRIVE_LAYOUT_INFORMATION_EX* layout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(layoutBuffer);
    std::cout << "分区样式: " << (layout->PartitionStyle == PARTITION_STYLE_MBR ? "MBR" : "GPT") << std::endl;
    std::cout << "分区数量: " << layout->PartitionCount << std::endl;

    // 打印每个分区的详细信息
    for (DWORD i = 0; i < layout->PartitionCount; ++i) {
        PARTITION_INFORMATION_EX& partition = layout->PartitionEntry[i];
        std::cout << "分区 " << i
            << ": 编号 " << partition.PartitionNumber
            << ", 起始偏移: " << partition.StartingOffset.QuadPart
            << ", 长度: " << partition.PartitionLength.QuadPart<< " 字节" << std::endl;
    }

    CloseHandle(hDisk);
}

// 恢复分区表条目的简单逻辑
int  RestorePartitionEntry(const std::string& diskPath)
{
    HANDLE hDevice = CreateFileA(diskPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "无法打开磁盘，错误代码: " << GetLastError() << std::endl;
        return 1;
    }

    // 获取当前磁盘布局
    BYTE layoutBuffer[2048]; // 增加缓冲区大小以容纳更多分区
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL,
        0,
        layoutBuffer,
        sizeof(layoutBuffer),
        &bytesReturned,
        NULL)) {
        std::cerr << "获取磁盘布局失败，错误代码: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    // 解析当前布局
    DRIVE_LAYOUT_INFORMATION_EX* layout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(layoutBuffer);
    if (layout->PartitionStyle != PARTITION_STYLE_GPT) {
        std::cerr << "仅支持GPT分区样式" << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    // 创建新分区表（复制现有布局并添加新分区）
    DWORD newPartitionCount = 3; // 固定为3个分区
    size_t newLayoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * (newPartitionCount - 1);
    BYTE* newLayoutBuffer = new BYTE[newLayoutSize];
    DRIVE_LAYOUT_INFORMATION_EX* newLayout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(newLayoutBuffer);

    // 初始化新布局
    memcpy(newLayout, layout, sizeof(DRIVE_LAYOUT_INFORMATION_EX)); // 复制基本信息
    newLayout->PartitionCount = newPartitionCount;

    // 分区0：保留原有的保留分区（编号1）
    memcpy(&newLayout->PartitionEntry[0], &layout->PartitionEntry[0], sizeof(PARTITION_INFORMATION_EX));

    // 分区1：新恢复的分区（编号2，排在前面）
    PARTITION_INFORMATION_EX& recoveredPartition = newLayout->PartitionEntry[1];
    recoveredPartition.PartitionStyle = PARTITION_STYLE_GPT;
    recoveredPartition.StartingOffset.QuadPart = 16777216;         // 新分区起始偏移
    recoveredPartition.PartitionLength.QuadPart = 1000197849088;   // 新分区长度
    recoveredPartition.PartitionNumber = 2;                        // 编号2
    recoveredPartition.Gpt.PartitionType = { 0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7} }; // NTFS GUID
    recoveredPartition.Gpt.Attributes = 0;
    wcscpy_s(recoveredPartition.Gpt.Name, L"Recovered");

    // 分区2：原有的931GB分区（编号3，移到后面）
    PARTITION_INFORMATION_EX& originalPartition = newLayout->PartitionEntry[2];
    memcpy(&originalPartition, &layout->PartitionEntry[1], sizeof(PARTITION_INFORMATION_EX)); // 复制原有分区1的信息
    originalPartition.PartitionNumber = 3; // 更新编号为3

    // 更新磁盘布局
    if (!DeviceIoControl(hDevice,
        IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
        newLayoutBuffer,
        static_cast<DWORD>(newLayoutSize),
        NULL,
        0,
        &bytesReturned,
        NULL)) {
        std::cerr << "更新分区表失败，错误代码: " << GetLastError() << std::endl;
        delete[] newLayoutBuffer;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "分区表更新成功，请检查磁盘管理" << std::endl;

    // 清理
    delete[] newLayoutBuffer;
    CloseHandle(hDevice);
    return 0;
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
    //RestorePartitionEntry(diskPath);

    //parseMFT();
    return 0;
}
