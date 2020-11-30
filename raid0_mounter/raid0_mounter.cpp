//
// @Noema 2020-11-28
//
// 参考:
// https://github.com/dokan-dev/dokany/blob/master/samples/dokan_mirror/mirror.c
//
//

#include "stdafx.h"

#include "../includes/dokan.h"

#define RAID0_VOLUME_NAME	L"镜像文件"

#define MAX_RAID0_IMAGEFILES		2
#define RAID0_STRIPE_SIZE			(4 << 20) // 4M
#define RAID0_IMAGE_OFFSET			(4 << 20)

typedef unsigned long (WINAPI *FN_dokan_version)();
typedef unsigned long (WINAPI *FN_dokan_driver_version)();
typedef int (WINAPI *FN_dokan_main)(PDOKAN_OPTIONS options, PDOKAN_OPERATIONS operations);
typedef int (WINAPI *FN_dokan_unmount)(wchar_t drive_letter);
typedef NTSTATUS (WINAPI *FN_dokan_ntstatusfromwin32)(unsigned long error);
typedef void (WINAPI *FN_dokan_mapkernel_to_usercreatefileflags)(
	ACCESS_MASK DesiredAccess,
	ULONG FileAttributes,
	ULONG CreateOptions,
	ULONG CreateDisposition,
	ACCESS_MASK *outDesiredAccess,
	DWORD *outFileAttributesAndFlags,
	DWORD *outCreationDisposition
	);

struct dokan_functions 
{
	FN_dokan_version			dokan_version;
	FN_dokan_driver_version		dokan_driver_version;
	FN_dokan_main				dokan_main;
	FN_dokan_unmount			dokan_unmount;
	FN_dokan_ntstatusfromwin32	dokan_ntstatusfromwin32;
	FN_dokan_mapkernel_to_usercreatefileflags dokan_mapkerneltousercreatefileflags;
};

typedef struct _read_disk_info 
{
	HANDLE				file_handle;
	LARGE_INTEGER		offset;
	ULONG				to_read;

}READ_DISK_INFO, *LPREAD_DISK_INFO;

struct raid0_info 
{
	HANDLE						handle;
	HANDLE						handle1;
};

struct global_info
{
	wchar_t						root_path[MAX_PATH];		// 第一个盘
	wchar_t						root_path1[MAX_PATH];		// 第二个盘

};

struct dokan_functions dokan_funcs = { 0 };
struct global_info ginfo = { 0 };
LARGE_INTEGER g_image_offset = { 0 };



int dokan_init_functions(struct dokan_functions *dokan_funcs, HMODULE *_dokan_module)
{
	int			ret = -1;
	HMODULE		dokan_module = NULL;

	if (!dokan_funcs || !_dokan_module)
	{
		return -1;
	}

	dokan_module = LoadLibraryExW(L"dokan1.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (dokan_module == NULL)
	{
		return -1;
	}

	do 
	{
		dokan_funcs->dokan_version = (FN_dokan_version)GetProcAddress(dokan_module, "DokanVersion");
		dokan_funcs->dokan_driver_version = (FN_dokan_driver_version)GetProcAddress(dokan_module, "DokanDriverVersion");
		dokan_funcs->dokan_main = (FN_dokan_main)GetProcAddress(dokan_module, "DokanMain");
		dokan_funcs->dokan_unmount = (FN_dokan_unmount)GetProcAddress(dokan_module, "DokanUnmount");
		dokan_funcs->dokan_ntstatusfromwin32 = (FN_dokan_ntstatusfromwin32)GetProcAddress(dokan_module, "DokanNtStatusFromWin32");
		dokan_funcs->dokan_mapkerneltousercreatefileflags = (FN_dokan_mapkernel_to_usercreatefileflags)GetProcAddress(dokan_module, "DokanMapKernelToUserCreateFileFlags");

		if (
			dokan_funcs->dokan_main == NULL ||
			dokan_funcs->dokan_unmount == NULL ||
			dokan_funcs->dokan_ntstatusfromwin32 == NULL || 
			dokan_funcs->dokan_mapkerneltousercreatefileflags == NULL
			)
		{
			break;
		}

		*_dokan_module = dokan_module;

		ret = 0;
	
	} while (0);

	if (ret != 0)
	{
		FreeLibrary(dokan_module);
	}

	return 0;
}


static
void WINAPI utils_get_file_path(PWCHAR filePath, ULONG numberOfElements, LPCWSTR FileName) 
{
  wcsncpy_s(filePath, numberOfElements, ginfo.root_path, wcslen(ginfo.root_path));

  //size_t unclen = wcslen(UNCName);

  //if (unclen > 0 && _wcsnicmp(FileName, UNCName, unclen) == 0) 
  //{
//	  if (_wcsnicmp(FileName + unclen, L".", 1) != 0) 
//	  {
//		  wcsncat_s(filePath, numberOfElements, FileName + unclen, wcslen(FileName) - unclen);
//	  }
  //} 
  //else 
  //{
	  wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
  //}

  return;
}

static
void WINAPI utils_get_file_path_ex(
	PWCHAR filePath,
	ULONG numberOfElements,
	PWCHAR filePath1,
	ULONG numberOfElements1,
	LPCWSTR FileName
)
{
	wcsncpy_s(filePath, numberOfElements, ginfo.root_path, wcslen(ginfo.root_path));
	wcsncpy_s(filePath1, numberOfElements1, ginfo.root_path1, wcslen(ginfo.root_path1));

	wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
	wcsncat_s(filePath1, numberOfElements1, FileName, wcslen(FileName));

	return;
}

NTSTATUS WINAPI raid0_create_file(
	LPCWSTR FileName,
	PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	WCHAR real_file_path[MAX_PATH] = { 0 };
	WCHAR real_file_path1[MAX_PATH] = { 0 };
	DWORD file_attributes = 0;
	DWORD file_attributes1 = 0;
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	HANDLE file_handle1 = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES security_attributes;

	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	ACCESS_MASK genericDesiredAccess;

	DWORD error_code = NO_ERROR;

	struct raid0_info *rdinfo = NULL;


	do 
	{
		dokan_funcs.dokan_mapkerneltousercreatefileflags(
				DesiredAccess,
				FileAttributes,
				CreateOptions,
				CreateDisposition,
				&genericDesiredAccess,
				&fileAttributesAndFlags,
				&creationDisposition
			);

		security_attributes.nLength = sizeof(security_attributes);
		security_attributes.lpSecurityDescriptor = SecurityContext->AccessState.SecurityDescriptor;
		security_attributes.bInheritHandle = FALSE;

		utils_get_file_path_ex(real_file_path, MAX_PATH, real_file_path1, MAX_PATH, FileName);

		wprintf(L"raid0_create_file: real_file_path = %ws \n", real_file_path);
		wprintf(L"raid0_create_file: real_file_path1 = %ws \n", real_file_path1);

		file_attributes = GetFileAttributesW(real_file_path);
		file_attributes1 = GetFileAttributesW(real_file_path1);

		if ( 
			(file_attributes != INVALID_FILE_ATTRIBUTES && (file_attributes & FILE_ATTRIBUTE_DIRECTORY)) && 
			(file_attributes1 != INVALID_FILE_ATTRIBUTES && (file_attributes1 & FILE_ATTRIBUTE_DIRECTORY)) 
			)
		{
			if (!(CreateOptions & FILE_NON_DIRECTORY_FILE))
			{
				DokanFileInfo->IsDirectory = TRUE;
				ShareAccess |= FILE_SHARE_READ;
			}
			else
			{
				ret_status = STATUS_FILE_IS_A_DIRECTORY;
				break;
			}
		}

		// 文件夹
		if (DokanFileInfo->IsDirectory)
		{
			//
			// NOTE：
			// 这里只关心读数据情况，暂不考虑写的情况（创建文件夹）
			//

			file_handle = CreateFileW(real_file_path, genericDesiredAccess, ShareAccess, &security_attributes, OPEN_EXISTING, fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (file_handle == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_create_file: CreateFileW directory failed, %d, %ws \n", error_code, real_file_path);
				break;
			}

			file_handle1 = CreateFileW(real_file_path1, genericDesiredAccess, ShareAccess, &security_attributes, OPEN_EXISTING, fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (file_handle1 == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_create_file: CreateFileW directory failed, %d, %ws \n", error_code, real_file_path1);
				break;
			}

			rdinfo = (struct raid0_info *)calloc(1, sizeof(struct raid0_info));
			if (rdinfo == NULL)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				printf("raid0_create_file: calloc failed \n", error_code);
				break;
			}
			rdinfo->handle = file_handle;
			rdinfo->handle1 = file_handle1;

			DokanFileInfo->Context = (ULONG64)rdinfo;
			if (creationDisposition == OPEN_ALWAYS && file_attributes != INVALID_FILE_ATTRIBUTES)
			{
				ret_status = STATUS_OBJECT_NAME_COLLISION;
				break;
			}

		}
		// 文件
		else
		{
			//
			// NOTE：
			// 这里只关心读数据情况，暂不考虑写的情况（创建、写入文件）
			//

			file_handle = CreateFileW(real_file_path, genericDesiredAccess, ShareAccess, &security_attributes, creationDisposition, fileAttributesAndFlags, NULL);
			if (file_handle == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_create_file: CreateFileW failed, %d, %ws \n", error_code, real_file_path);
				break;
			}

			file_handle1 = CreateFileW(real_file_path1, genericDesiredAccess, ShareAccess, &security_attributes, creationDisposition, fileAttributesAndFlags, NULL);
			if (file_handle1 == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_create_file: CreateFileW failed, %d, %ws \n", error_code, real_file_path1);
				break;
			}

			rdinfo = (struct raid0_info *)calloc(1, sizeof(struct raid0_info));
			if (rdinfo == NULL)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				printf("raid0_create_file: calloc failed \n", error_code);
				break;
			}
			rdinfo->handle = file_handle;
			rdinfo->handle1 = file_handle1;

			DokanFileInfo->Context = (ULONG64)rdinfo;

			if (creationDisposition == OPEN_ALWAYS || creationDisposition == CREATE_ALWAYS)
			{
				if (GetLastError() == ERROR_ALREADY_EXISTS)
				{
					ret_status = STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}

		ret_status = STATUS_SUCCESS;

	} while (0);

	return ret_status;
}

void WINAPI raid0_close_file(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo)
{
	struct raid0_info *rdinfo = NULL;

	if (DokanFileInfo->Context)
	{
		rdinfo = (struct raid0_info *)DokanFileInfo->Context;

		if (rdinfo->handle && rdinfo->handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(rdinfo->handle);
		}
		if (rdinfo->handle1 && rdinfo->handle1 != INVALID_HANDLE_VALUE)
		{
			CloseHandle(rdinfo->handle1);
		}

		free(rdinfo);

		DokanFileInfo->Context = NULL;
	}
	else
	{
		//
	}

	return;
}

void WINAPI raid0_clean_file(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo)
{
	struct raid0_info *rdinfo = NULL;

	if (DokanFileInfo->Context)
	{
		rdinfo = (struct raid0_info *)DokanFileInfo->Context;

		if (rdinfo->handle && rdinfo->handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(rdinfo->handle);
		}
		if (rdinfo->handle1 && rdinfo->handle1 != INVALID_HANDLE_VALUE)
		{
			CloseHandle(rdinfo->handle1);
		}

		free(rdinfo);

		DokanFileInfo->Context = NULL;
	}
	else
	{
		//
	}

	//
	// TODO: 
	// delete on close etc.
	// 我们的目标是查看，不进行修改，删除更不可能,暂不实现删除功能
	//

	return;
}

NTSTATUS WINAPI raid0_get_file_information(
	LPCWSTR wcsFileName,
	LPBY_HANDLE_FILE_INFORMATION hfi,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	HANDLE file_handle1 = INVALID_HANDLE_VALUE;
	WCHAR real_file_path[MAX_PATH] = { 0 };
	WCHAR real_file_path1[MAX_PATH] = { 0 };
	WIN32_FILE_ATTRIBUTE_DATA file_att_data = { 0 };
	WIN32_FILE_ATTRIBUTE_DATA file_att_data1 = { 0 };
	BY_HANDLE_FILE_INFORMATION handle_info;
	BY_HANDLE_FILE_INFORMATION handle_info1;

	DWORD error_code = NO_ERROR;
	BOOL opened = FALSE;
	BOOL opened1 = FALSE;
	BOOL is_root_path = FALSE;

	struct raid0_info *rdinfo = NULL;

	do 
	{
		utils_get_file_path_ex(real_file_path, MAX_PATH, real_file_path1, MAX_PATH, wcsFileName);

		rdinfo = (struct raid0_info *)DokanFileInfo->Context;
		if (rdinfo == NULL)
		{
			file_handle = NULL;
			file_handle1 = NULL;
		}
		else
		{
			file_handle = rdinfo->handle;
			file_handle1 = rdinfo->handle1;
		}

		if (file_handle == NULL || file_handle == INVALID_HANDLE_VALUE)
		{
			file_handle = CreateFileW(real_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (file_handle == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_get_file_information: CreateFileW failed, %d, %ws \n", error_code, real_file_path);
				break;
			}

			opened = TRUE;
		}

		if (file_handle1 == NULL || file_handle1 == INVALID_HANDLE_VALUE)
		{
			file_handle1 = CreateFileW(real_file_path1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (file_handle1 == INVALID_HANDLE_VALUE)
			{
				error_code = GetLastError();
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
				wprintf(L"raid0_get_file_information: CreateFileW failed, %d, %ws \n", error_code, real_file_path1);
				break;
			}

			opened1 = TRUE;
		}

		if ( !GetFileInformationByHandle(file_handle, &handle_info) )
		{
			if (wcsicmp(wcsFileName, L"\\") == 0)
			{
				is_root_path = TRUE;
				hfi->dwFileAttributes = GetFileAttributesW(real_file_path);
			}
			else
			{
				if (!GetFileAttributesExW(real_file_path, GetFileExInfoStandard, &file_att_data))
				{
					error_code = GetLastError();
					ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
					break;
				}

				handle_info.dwFileAttributes = file_att_data.dwFileAttributes;
				handle_info.ftCreationTime = file_att_data.ftCreationTime;
				handle_info.ftLastAccessTime = file_att_data.ftLastAccessTime;
				handle_info.ftLastWriteTime = file_att_data.ftLastWriteTime;
				handle_info.nFileSizeHigh = file_att_data.nFileSizeHigh;
				handle_info.nFileSizeLow = file_att_data.nFileSizeLow;
			}
		}

		if ( !GetFileInformationByHandle(file_handle1, &handle_info1) )
		{
			if (wcsicmp(wcsFileName, L"\\") == 0)
			{
				is_root_path = TRUE;
				hfi->dwFileAttributes = GetFileAttributesW(real_file_path1);
			}
			else
			{
				if (!GetFileAttributesExW(real_file_path1, GetFileExInfoStandard, &file_att_data1))
				{
					error_code = GetLastError();
					ret_status = dokan_funcs.dokan_ntstatusfromwin32(error_code);
					break;
				}

				handle_info1.dwFileAttributes = file_att_data1.dwFileAttributes;
				handle_info1.ftCreationTime = file_att_data1.ftCreationTime;
				handle_info1.ftLastAccessTime = file_att_data1.ftLastAccessTime;
				handle_info1.ftLastWriteTime = file_att_data1.ftLastWriteTime;
				handle_info1.nFileSizeHigh = file_att_data1.nFileSizeHigh;
				handle_info1.nFileSizeLow = file_att_data1.nFileSizeLow;
			}
		}

		// NOTE:
		// 计算文件总大小
		if ( !is_root_path )
		{
			hfi->dwFileAttributes = handle_info.dwFileAttributes; // or handle_info.dwFileAttributes
			hfi->ftCreationTime = handle_info.ftCreationTime;
			hfi->ftLastAccessTime = handle_info.ftLastAccessTime;
			hfi->ftLastWriteTime = handle_info.ftLastWriteTime;
			hfi->nFileSizeHigh = handle_info.nFileSizeHigh + handle_info1.nFileSizeHigh;
			hfi->nFileSizeLow = handle_info.nFileSizeLow + handle_info1.nFileSizeLow;
			
			LARGE_INTEGER tmp;
			tmp.HighPart = hfi->nFileSizeHigh;
			tmp.LowPart = hfi->nFileSizeLow;
			tmp.QuadPart -= (g_image_offset.QuadPart * 2);

			hfi->nFileSizeHigh = tmp.HighPart;
			hfi->nFileSizeLow = tmp.LowPart;
		}

		ret_status = STATUS_SUCCESS;

	} while (0);

	if (opened)
	{
		CloseHandle(file_handle);
	}
	if (opened1)
	{
		CloseHandle(file_handle1);
	}

	return ret_status;
}

NTSTATUS WINAPI raid0_find_files(
	LPCWSTR FileName,
	PFillFindData FillFindData,		 // function pointer
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	WCHAR real_file_path[MAX_PATH] = { 0 };
	WCHAR real_file_path1[MAX_PATH] = { 0 };
	WCHAR real_file_path_full_name1[MAX_PATH] = { 0 };
	UINT real_file_path_len = 0;
	UINT real_file_path_len1 = 0;
	HANDLE find_handle = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW find_data = { 0 };
	DWORD error = NO_ERROR;

	do 
	{
		utils_get_file_path_ex(real_file_path, MAX_PATH, real_file_path1, MAX_PATH, FileName);

		real_file_path_len = wcslen(real_file_path);
		real_file_path_len1 = wcslen(real_file_path1);

		if (real_file_path[real_file_path_len - 1] != L'\\')
		{
			real_file_path[real_file_path_len++] = L'\\';
		}
		if (real_file_path_len + 1 >= MAX_PATH)
		{
			ret_status = STATUS_BUFFER_OVERFLOW;
			break;
		}
		real_file_path[real_file_path_len] = L'*';
		real_file_path[real_file_path_len + 1] = L'\0';

		//
		if (real_file_path1[real_file_path_len1 - 1] != L'\\')
		{
			real_file_path1[real_file_path_len1++] = L'\\';
		}
		real_file_path1[real_file_path_len1] = L'\0';

		find_handle = FindFirstFileW(real_file_path, &find_data);
		if (find_handle == INVALID_HANDLE_VALUE)
		{
			ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
			break;
		}

		do 
		{
			// 避免Root目录
			if ( (wcsicmp(FileName, L"\\") != 0) || (wcscmp(find_data.cFileName, L".") != 0 && wcscmp(find_data.cFileName, L"..") != 0) )
			{
				if (FillFindData)
				{
					// 在第二个位置超找是否存在相同的文件名的文件
					wsprintfW(real_file_path_full_name1, L"%ws%ws", real_file_path1, find_data.cFileName);

					WIN32_FILE_ATTRIBUTE_DATA file_info_data = { 0 };
					if (GetFileAttributesExW(real_file_path_full_name1, GetFileExInfoStandard, &file_info_data) && file_info_data.dwFileAttributes != INVALID_FILE_ATTRIBUTES)
					{
						find_data.nFileSizeHigh += file_info_data.nFileSizeHigh;
						find_data.nFileSizeLow += file_info_data.nFileSizeLow;

						LARGE_INTEGER tmp;
						tmp.HighPart = find_data.nFileSizeHigh;
						tmp.LowPart = find_data.nFileSizeLow;
						tmp.QuadPart -= (g_image_offset.QuadPart * 2);

						find_data.nFileSizeHigh = tmp.HighPart;
						find_data.nFileSizeLow = tmp.LowPart;

						// 投递找到的文件(文件夹)
						FillFindData(&find_data, DokanFileInfo);
					}
				}
			}
		} while (FindNextFileW(find_handle, &find_data));

		error = GetLastError();

		FindClose(find_handle);

		if (error != ERROR_NO_MORE_FILES)
		{
			ret_status = dokan_funcs.dokan_ntstatusfromwin32(error);
			break;
		}

		ret_status = STATUS_SUCCESS;

	} while (0);

	return ret_status;
}


NTSTATUS WINAPI raid0_read_file(
	LPCWSTR FileName, 
	LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	WCHAR real_file_path[MAX_PATH] = { 0 };
	WCHAR real_file_path1[MAX_PATH] = { 0 };
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	HANDLE file_handle1 = INVALID_HANDLE_VALUE;
	BOOL opened = FALSE;
	BOOL opened1 = FALSE;

	struct raid0_info *_rdinfo = NULL;
		
	do 
	{
		utils_get_file_path_ex(real_file_path, MAX_PATH, real_file_path1, MAX_PATH, FileName);

		// NOTE: DokanFileInfo->Context == NULL ?????
		_rdinfo = (struct raid0_info *)DokanFileInfo->Context;
		if (_rdinfo == NULL)
		{
			file_handle = NULL;
			file_handle1 = NULL;
		}
		else
		{
			file_handle = _rdinfo->handle;
			file_handle1 = _rdinfo->handle1;
		}

		if (file_handle == NULL || file_handle == INVALID_HANDLE_VALUE)
		{
			file_handle = CreateFileW(real_file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (file_handle == INVALID_HANDLE_VALUE)
			{
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
				break;
			}

			opened = TRUE;
		}
		if (file_handle1 == NULL || file_handle1 == INVALID_HANDLE_VALUE)
		{
			file_handle1 = CreateFileW(real_file_path1, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (file_handle1 == INVALID_HANDLE_VALUE)
			{
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
				break;
			}

			opened1 = TRUE;
		}

		LARGE_INTEGER	blocks_at_offset;	
		ULONG			offset_in_block;
		UINT32			disk_index;

		ULONG			stripe_size = 0;
		ULONG			readed = 0;
		ULONG			_readed = 0;
		ULONG			toread = 0;
		LARGE_INTEGER	tooffset;
		LARGE_INTEGER	new_byteoffset;

		READ_DISK_INFO	rdinfo[MAX_RAID0_IMAGEFILES] = { 0 };
		UINT32			rdinfo_index = 0;
		UINT32			image_file_count = MAX_RAID0_IMAGEFILES;

		ULONGLONG		image_offset = g_image_offset.QuadPart;	// 根据实际情况设置该值


		new_byteoffset.QuadPart = Offset;

		stripe_size = RAID0_STRIPE_SIZE;

		blocks_at_offset.QuadPart = new_byteoffset.QuadPart / stripe_size;
		offset_in_block = new_byteoffset.QuadPart % stripe_size; 


		//
		// 初始化各个磁盘镜像参数
		//

		// 初始化文件句柄
		rdinfo[0].file_handle = file_handle;
		rdinfo[1].file_handle = file_handle1;

		disk_index = blocks_at_offset.QuadPart % image_file_count;
		rdinfo_index = disk_index;

		rdinfo[rdinfo_index].offset.QuadPart = (blocks_at_offset.QuadPart / image_file_count) * stripe_size;
		for (UINT32 idx=0; idx<image_file_count; idx++)
		{
			if (idx < rdinfo_index)
			{
				rdinfo[idx].offset.QuadPart = rdinfo[rdinfo_index].offset.QuadPart + stripe_size;
			}
			else if (idx > rdinfo_index)
			{
				rdinfo[idx].offset.QuadPart = rdinfo[rdinfo_index].offset.QuadPart;
			}
		}
		rdinfo[rdinfo_index].offset.QuadPart += offset_in_block;

		rdinfo[rdinfo_index].to_read = stripe_size - offset_in_block;
		if (rdinfo[rdinfo_index].to_read > (BufferLength))
		{
			rdinfo[rdinfo_index].to_read = (BufferLength);
		}

		//
		// 读取磁盘镜像文件
		//

		do
		{
			tooffset.QuadPart = rdinfo[rdinfo_index].offset.QuadPart + image_offset;
			toread = rdinfo[rdinfo_index].to_read;

			LARGE_INTEGER distance_move;
			distance_move.QuadPart = tooffset.QuadPart;
			if (!SetFilePointerEx(rdinfo[rdinfo_index].file_handle, distance_move, NULL, FILE_BEGIN))
			{
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
				break;
			}

			if (!ReadFile(rdinfo[rdinfo_index].file_handle, (PBYTE)Buffer + readed, toread, &_readed, NULL))
			{
				*ReadLength = 0;
				ZeroMemory(Buffer, BufferLength);
				ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
				break;
			}
			if (_readed == 0)
			{
				*ReadLength = readed;
				ret_status = STATUS_SUCCESS;
				break;
			}

			readed += _readed;

			//if (_readed != toread)
			//{
			//	*ReadLength = readed;
			//	ret_status = STATUS_SUCCESS;
			//	break;
			//}

			if ((BufferLength - readed) == 0)
			{
				*ReadLength = readed;
				ret_status = STATUS_SUCCESS;
				break;
			}

			if ((BufferLength - readed) >= stripe_size)
			{
				toread = stripe_size;
			}
			else
			{
				toread = BufferLength - readed;
			}

			rdinfo[rdinfo_index].offset.QuadPart += _readed;

			rdinfo_index++;
			rdinfo_index %= image_file_count;

			rdinfo[rdinfo_index].to_read = toread;

		} while (TRUE);

	} while (0);

	if (opened)
	{
		CloseHandle(file_handle);
	}
	if (opened1)
	{
		CloseHandle(file_handle1);
	}

	return ret_status;
}

NTSTATUS WINAPI raid0_get_file_security(
	LPCWSTR FileName,
	PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG BufferLength,
	PULONG LengthNeeded,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	WCHAR real_file_path[MAX_PATH] = { 0 };
	BOOLEAN requestingSaclInfo;
	HANDLE file_handle = INVALID_HANDLE_VALUE;


	do
	{
		utils_get_file_path(real_file_path, MAX_PATH, FileName);

		requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) || (*SecurityInformation & BACKUP_SECURITY_INFORMATION));

		file_handle = CreateFile(
			real_file_path,
			READ_CONTROL | ((requestingSaclInfo) ? ACCESS_SYSTEM_SECURITY : 0),
			FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
			NULL, // security attribute
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
			NULL);

		if (!file_handle || file_handle == INVALID_HANDLE_VALUE)
		{
			ret_status = dokan_funcs.dokan_ntstatusfromwin32(GetLastError());
			break;
		}

		if (!GetUserObjectSecurity(
			file_handle,
			SecurityInformation,
			SecurityDescriptor,
			BufferLength,
			LengthNeeded))
		{
			int error = GetLastError();
			if (error == ERROR_INSUFFICIENT_BUFFER)
			{
				ret_status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			ret_status = dokan_funcs.dokan_ntstatusfromwin32(error);
			break;
		}
  
		// Ensure the Security Descriptor Length is set
		DWORD securityDescriptorLength = GetSecurityDescriptorLength(SecurityDescriptor);
	  
		*LengthNeeded = securityDescriptorLength;

		ret_status = STATUS_SUCCESS;

	} while (0);

	if (file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
	}

	return ret_status;
}

NTSTATUS WINAPI raid0_get_volume_information(
	LPWSTR VolumeNameBuffer,
	DWORD VolumeNameSize,
	LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength,
	LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer,
	DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	NTSTATUS ret_status = STATUS_NOT_IMPLEMENTED;
	WCHAR volume_root[4] = { 0 };
	DWORD file_system_flags;

	do 
	{
		wcscpy_s(VolumeNameBuffer, VolumeNameSize, RAID0_VOLUME_NAME);

		if (VolumeSerialNumber)
		{
			*VolumeSerialNumber = 0x19890303;
		}
		if (MaximumComponentLength)
		{
			*MaximumComponentLength = 255;
		}
		if (FileSystemFlags)
		{
			*FileSystemFlags = FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;
		}

		volume_root[0] = ginfo.root_path[0];
		volume_root[1] = L':';
		volume_root[2] = L'\\';
		volume_root[3] = L'\0';

		if ( GetVolumeInformationW(volume_root, NULL, 0, NULL, MaximumComponentLength, &file_system_flags, FileSystemNameBuffer, FileSystemNameSize))
		{
			if (FileSystemFlags)
			{
				*FileSystemFlags &= file_system_flags;
			}
		}
		else
		{
			wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
		}

		ret_status = STATUS_SUCCESS;

	} while (0);

	return ret_status;
}


NTSTATUS WINAPI raid0_get_disk_free_space(
	PULONGLONG FreeBytesAvailable, 
	PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, 
	PDOKAN_FILE_INFO DokanFileInfo) 
{
	  DWORD SectorsPerCluster;
	  DWORD BytesPerSector;
	  DWORD NumberOfFreeClusters;
	  DWORD TotalNumberOfClusters;
	  WCHAR DriveLetter[3] = {'C', ':', 0};
	  PWCHAR RootPathName;

	  // 第一个盘大小
	  DriveLetter[0] = ginfo.root_path[0];
	  RootPathName = DriveLetter;

	  GetDiskFreeSpace(RootPathName, &SectorsPerCluster, &BytesPerSector,
	                   &NumberOfFreeClusters, &TotalNumberOfClusters);

	  *FreeBytesAvailable =
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	  *TotalNumberOfFreeBytes =
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	  *TotalNumberOfBytes =
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * TotalNumberOfClusters;

	  // 第二个盘大小，累加
	  DriveLetter[0] = ginfo.root_path1[0];
	  RootPathName = DriveLetter;

	  GetDiskFreeSpace(RootPathName, &SectorsPerCluster, &BytesPerSector,
	                   &NumberOfFreeClusters, &TotalNumberOfClusters);

	  *FreeBytesAvailable +=
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	  *TotalNumberOfFreeBytes +=
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	  *TotalNumberOfBytes +=
	      ((ULONGLONG)SectorsPerCluster) * BytesPerSector * TotalNumberOfClusters;
	  
	  return STATUS_SUCCESS;
}

NTSTATUS WINAPI raid0_mounted(PDOKAN_FILE_INFO DokanFileInfo)
{
	printf("Mounted \n");
	return STATUS_SUCCESS;
}

NTSTATUS WINAPI raid0_unmounted(PDOKAN_FILE_INFO DokanFileInfo)
{
	printf("UnMounted \n");
	return STATUS_SUCCESS;
}

int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE dokan_module = NULL;

	wcsncpy(ginfo.root_path, L"F:", sizeof(ginfo.root_path) / sizeof(ginfo.root_path[0]) - 1);
	wcsncpy(ginfo.root_path1, L"H:", sizeof(ginfo.root_path1) / sizeof(ginfo.root_path1[0]) - 1);
	
	if (argc > 3)
	{
		ginfo.root_path[0] = (WCHAR)argv[1];
		ginfo.root_path1[0] = (WCHAR)argv[2];
	}
	
	g_image_offset.QuadPart = RAID0_IMAGE_OFFSET;

	if (dokan_init_functions(&dokan_funcs, &dokan_module) != 0)
	{
		printf("error: dokan_init_functions failed!!! install dokan runtime. \n");
		return -1;
	}

	printf("dokan version: %d \n", dokan_funcs.dokan_version());
	printf("dokan driver version: %d \n", dokan_funcs.dokan_driver_version());


	PDOKAN_OPTIONS dokan_options = NULL;
	PDOKAN_OPERATIONS dokan_operations = NULL;

	dokan_options = (PDOKAN_OPTIONS)calloc(1, sizeof(DOKAN_OPTIONS));
	dokan_operations = (PDOKAN_OPERATIONS)calloc(1, sizeof(DOKAN_OPERATIONS));

	dokan_options->Version = DOKAN_VERSION;
	dokan_options->Options |= DOKAN_OPTION_WRITE_PROTECT | DOKAN_OPTION_ALT_STREAM;
	dokan_options->UNCName = RAID0_VOLUME_NAME;
	dokan_options->MountPoint = L"J:\\";
	dokan_options->ThreadCount = 10;
	dokan_options->Timeout = 60 * 1000;

	dokan_operations->ZwCreateFile = raid0_create_file;
	dokan_operations->GetFileInformation = raid0_get_file_information;
	dokan_operations->Cleanup = raid0_clean_file;
	dokan_operations->CloseFile = raid0_close_file;
	dokan_operations->FindFiles = raid0_find_files;
	dokan_operations->ReadFile = raid0_read_file;
	dokan_operations->GetFileSecurityW = raid0_get_file_security;
	dokan_operations->GetVolumeInformationW = raid0_get_volume_information;
	dokan_operations->GetDiskFreeSpaceW = raid0_get_disk_free_space;
	dokan_operations->Mounted = raid0_mounted;
	dokan_operations->Unmounted = raid0_unmounted;
	dokan_operations->FindFilesWithPattern = NULL;

	dokan_funcs.dokan_main(dokan_options, dokan_operations);

	dokan_funcs.dokan_unmount(L'J');

	if (dokan_module)
	{
		FreeLibrary(dokan_module);
	}

	if (dokan_options)
	{
		free(dokan_options);
	}
	if (dokan_operations)
	{
		free(dokan_operations);
	}


	return 0;
}

