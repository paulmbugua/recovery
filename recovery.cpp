#include <Windows.h>
#include <iostream>
#include <string>
#include "ntfs.h"
#include <stdlib.h>

ULONG BytesPerFileRecord;
HANDLE hvolume = INVALID_HANDLE_VALUE;
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT;

template <class T1, class T2> inline T1* Padd(T1* p, T2 n){
	return (T1*)((char*)p + n);
}

ULONG RunLength(PUCHAR run) {
	std::cout << "RunLength().." << std::endl;
	return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}

LONGLONG RunLCN(PUCHAR run) {
	LONG i = 0;
	UCHAR n1 = 0, n2 = 0;
	LONGLONG lcn = 0;
	std::cout << "RunLCN().." << std::endl;
	n1 = *run & 0xf;
	n2 = (*run >> 4) & 0xf;
	lcn = n2 == 0 ? 0 : CHAR(run[n1 + n2]);
	for (i = n1 + n2 - 1; i > n1; i--)
		lcn = (lcn << 8) + run[i];
	return lcn;
}

ULONGLONG RunCount(PUCHAR run){
	UCHAR n = *run & 0xf;
	ULONGLONG count = 0;
	ULONG i;
	std::cout << "RunCount().." << std::endl;
	for (i = n; i > 0; i--)
		count = (count << 8) + run[i];
	return count;
}

BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count){
	PUCHAR run = NULL;
	*lcn = 0;
	ULONGLONG base = attr->LowVcn;
	std::cout << "FindRun().." << std::endl;
	if (vcn < attr->LowVcn || vcn > attr->HighVcn)
		return FALSE;
	for (run = PUCHAR(Padd(attr, attr->RunArrayOffset)); *run != 0; run += RunLength(run)){
		*lcn += RunLCN(run);
		*count = RunCount(run);
		if (base <= vcn && vcn < base + *count){
			*lcn = RunLCN(run) == 0 ? 0 : *lcn + vcn - base;
			*count -= ULONG(vcn - base);
			return TRUE;
		}
		else
			base += *count;
	}
	return FALSE;
}



PATTRIBUTE FindAttribute(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name){
	PATTRIBUTE attr = NULL;
	std::cout << "FindAttibute().." << std::endl;
	for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset));
		attr->AttributeType != -1; attr = Padd(attr, attr->Length))
	{if (attr->AttributeType == type){
			if (name == 0 && attr->NameLength == 0)
				return attr;
			if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name,PWSTR(Padd(attr, attr->NameOffset))) == 0)
				return attr;
		}
	}
	return 0;
}

VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file){
	ULONG i = 0;
	PUSHORT usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
	PUSHORT sector = PUSHORT(file);
	std::cout << "FixupUpdateSequenceArray().." << std::endl;
	for (i = 1; i < file->Ntfs.UsaCount; i++){
		sector[255] = usa[i];
		sector += 256;
	}
}

VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer){
	ULARGE_INTEGER offset;
	OVERLAPPED overlap = { 0 };
	ULONG n;
	std::cout << "ReadSector().." << std::endl;
	std::cout << "sector: " << sector << std::endl;
	offset.QuadPart = sector * bootb.BytesPerSector;
	overlap.Offset = offset.LowPart;
	overlap.OffsetHigh = offset.HighPart;
	ReadFile(hvolume, buffer, count * bootb.BytesPerSector, &n, &overlap);
}

VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer){
	std::cout << "ReadLCN().." << std::endl;
	ReadSector(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
}

VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer){
	ULONGLONG lcn, runcount;
	ULONG readcount, left;
	PUCHAR bytes = PUCHAR(buffer);
	std::cout << "RunExternalAttribute().." << std::endl;
	for (left = count; left > 0; left -= readcount)	{
		FindRun(attr, vcn, &lcn, &runcount);
		readcount = ULONG(min(runcount, left));
		ULONG n = readcount * bootb.BytesPerSector * bootb.SectorsPerCluster;
		if (lcn == 0)
			memset(bytes, 0, n);
		else
		{	ReadLCN(lcn, readcount, bytes);
		std::cout << "LLCN:" << lcn << std::endl;
		}
		vcn += readcount;
		bytes += n;
	}
}

ULONG AttributeLength(PATTRIBUTE attr){
	std::cout << "AttributeLength().."<< std::endl;
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}

ULONG AttributeLengthAllocated(PATTRIBUTE attr){
	std::cout << "AttributeLengthAllocated().." << std::endl;
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}

VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer){
	PRESIDENT_ATTRIBUTE rattr = NULL;
	PNONRESIDENT_ATTRIBUTE nattr = NULL;
	std::cout << "ReadAttribute().." << std::endl;
	if (attr->Nonresident == FALSE)	{
		std::cout << "Resident attribute.." << std::endl;
		rattr = PRESIDENT_ATTRIBUTE(attr);
		memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength);
	}
	else{
		std::cout << "Non-resident attribute.." << std::endl;
		nattr = PNONRESIDENT_ATTRIBUTE(attr);
		ReadExternalAttribute(nattr, 0, ULONG(nattr->HighVcn) + 1, buffer);
	}
}

VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer){
	PATTRIBUTE attrlist = NULL;
	PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file, type, 0));
	std::cout << "ReadVCN().." << std::endl;
	if (attr == 0 || (vcn < attr->LowVcn || vcn > attr->HighVcn)){
		attrlist = FindAttribute(file, AttributeAttributeList, 0);
		DebugBreak();
	}
	ReadExternalAttribute(attr, vcn, count, buffer);
}

VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file){
	ULONG clusters = bootb.ClustersPerFileRecord;
	std::cout << "ReadFileRecord().." << std::endl;
	if (clusters > 0x80)
		clusters = 1;
	PUCHAR p = new UCHAR[bootb.BytesPerSector * bootb.SectorsPerCluster * clusters];
	ULONGLONG vcn = ULONGLONG(index) * BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;
	ReadVCN(MFT, AttributeData, vcn, clusters, p);
	LONG m = (bootb.SectorsPerCluster * bootb.BytesPerSector / BytesPerFileRecord) - 1;
	ULONG n = m > 0 ? (index & m) : 0;
	memcpy(file, p + n * BytesPerFileRecord, BytesPerFileRecord);
	delete[] p;
	FixupUpdateSequenceArray(file);
}

VOID LoadMFT(){
	std::cout << "LoadMFT().." << std::endl;
	 BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80
		? bootb.ClustersPerFileRecord * bootb.SectorsPerCluster
		* bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);

	std::cout<<"Bytes Per File Record ="<< BytesPerFileRecord<<std::endl;
	std::cout << "BootSectors = "<<bootb.BootSectors<<std::endl;
	std::cout << "bootb.BootSignature = " << bootb.BootSignature << std::endl;
	std::cout << "bootb.BytesPerSector = " << bootb.BytesPerSector << std::endl;
	std::cout << "bootb.ClustersPerFileRecord = " << bootb.ClustersPerFileRecord << std::endl;
	std::cout << "bootb.ClustersPerIndexBlock = " << bootb.ClustersPerIndexBlock << std::endl;
	std::cout << "bootb.Code = " << bootb.Code << std::endl;
	std::cout << "bootb.Format = " << bootb.Format << std::endl;
	std::cout << "bootb.Jump = " << bootb.Jump << std::endl;
	std::cout << "bootb.Mbz1 = " << bootb.Mbz1 << std::endl;
	std::cout << "bootb.Mbz2 = " << bootb.Mbz2 << std::endl;
	std::cout << "bootb.Mbz3 = " << bootb.Mbz3 << std::endl;
	std::cout << "bootb.MediaType = " << bootb.MediaType << std::endl;
	std::cout << "bootb.Mft2StartLcn = " << bootb.Mft2StartLcn << std::endl;
	std::cout << "bootb.MftStartLcn = " << bootb.MftStartLcn << std::endl;
	std::cout << "bootb.NumberOfHeads = " << bootb.NumberOfHeads << std::endl;
	std::cout << "bootb.PartitionOffset = "<< bootb.PartitionOffset << std::endl;
	std::cout << "bootb.SectorsPerCluster = "<< bootb.SectorsPerCluster << std::endl;
	std::cout << "bootb.SectorsPerTrack = "<< bootb.SectorsPerTrack << std::endl;
	std::cout << "bootb.TotalSectors = "<< bootb.TotalSectors << std::endl;
	std::cout << "bootb.VolumeSerialNumber = "<< bootb.VolumeSerialNumber.HighPart<<"  "<< bootb.VolumeSerialNumber.HighPart << std::endl;
	MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ReadSector((bootb.MftStartLcn) * (bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);
	FixupUpdateSequenceArray(MFT);
}

BOOL bitset(PUCHAR bitmap, ULONG i){
	return (bitmap[i >> 3] & (1 << (i & 7))) != 0;
}
VOID FindDeleted(){
	PATTRIBUTE attr = FindAttribute(MFT, AttributeBitmap, 0);
	PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];
	ReadAttribute(attr, bitmap);
	ULONG n = AttributeLength(FindAttribute(MFT, AttributeData, 0)) / BytesPerFileRecord;
	std::cout << "FindDeleted().." << std::endl;
	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	for (ULONG i = 0; i < n; i++){
		if (bitset(bitmap, i))
			continue;
		ReadFileRecord(i, file);
		if (file->Ntfs.Type == 'ELIF' && (file->Flags & 1) == 0){
			attr = FindAttribute(file, AttributeFileName, 0);
			if (attr == 0)
				continue;
			PFILENAME_ATTRIBUTE name = PFILENAME_ATTRIBUTE(Padd(attr, PRESIDENT_ATTRIBUTE(attr)->ValueOffset));
			std::cout<<"Name length :"<<name->NameLength<<"  "<<name->NameLength<<"  "<< name->Name<<std::endl;
		}
	}
}

VOID DumpData(ULONG index, WCHAR* filename){
	PATTRIBUTE attr = NULL;
	HANDLE hFile = NULL;
	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ULONG n;
	ReadFileRecord(index, file);
	std::cout << "DumpData().." << std::endl;
	if (file->Ntfs.Type != 'ELIF')
		return;
	attr = FindAttribute(file, AttributeData, 0);
	if (attr == 0)
		return;
	PUCHAR buf = new UCHAR[AttributeLengthAllocated(attr)];
	ReadAttribute(attr, buf);

	hFile = CreateFile((LPCSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE){
		std::cout << "CreateDumpFile()..Failed" << std::endl;
		return;
	}
	if (WriteFile(hFile, buf, AttributeLength(attr), &n, 0) == 0){
		std::cout << "WriteDumpFile()..Failed" << std::endl;
		return;
	}
	CloseHandle(hFile);
	delete[] buf;
}

bool isntfsdrive(std::string drive) {
	char format[MAXBYTE];	
	if (GetVolumeInformationA(drive.c_str(),NULL,NULL,NULL,NULL,0,(LPSTR)&format,MAX_PATH+1)) {
		std::cout << format << std::endl;
		if (strcmp(format, "NTFS")==0) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		std::cout << "GetVolumeInformation()" << GetLastError() << std::endl;
		return false;
	}
}

int main(int x,char *argv[] ) {
	if (x <= 1) {
		std::cout << "No drive passed" << std::endl;
		return 0;
	}
	std::string drive;	
	drive.append("\\\\.\\");
	drive.append(argv[1]);
	ULONG n;
	if (isntfsdrive(argv[1])) {
		
		hvolume = CreateFile(drive.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (hvolume == INVALID_HANDLE_VALUE) {
				if (hvolume) {
					CloseHandle(hvolume);
				}
				std::cout << "CreateFile() " << GetLastError() << std::endl;
			}
			else {
				if (ReadFile(hvolume, &bootb, sizeof bootb, &n, 0) == 0) {
					std::cout << "ReadFile() " << GetLastError() << std::endl;
				}
				else {
					LoadMFT();
					FindDeleted();
					DumpData(wcstoul((const wchar_t*)argv[1],0,0) , (WCHAR *)"recover.txt");
					CloseHandle(hvolume);
				}
			}
			
		
	}
	else {
		std::cout << "The drive is None NTFS " << std::endl;
	}
	system("pause");
	return 0;
}