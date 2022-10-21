/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "delta.h"

/*
 *  IMAGE/FLASH MANAGEMENT
 */

static int erase_page(struct flash_mem *flash, off_t offset)
{
	offset = offset - offset%PAGE_SIZE; /* find start of page */
	//printk("\r\nErase_page:address=%p\r\n", offset);
	// if (flash_write_protection_set(flash->device, false)) {
	// 	return -DELTA_CLEARING_ERROR;
	// }
	if (flash_erase(flash->device, offset, PAGE_SIZE)) {
		return -DELTA_CLEARING_ERROR;
	}
	// if (flash_write_protection_set(flash->device, true)) {
	// 	return -DELTA_CLEARING_ERROR;
	// }

	return DELTA_OK;
}

static int delta_flash_write(void *arg_p,
					const uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;
	flash->write_buf += size;
	size_t free_page_size = PAGE_SIZE - flash->to_current % PAGE_SIZE;

	//if ((flash->write_buf >= PAGE_SIZE) || ((flash->write_buf>0) && ((flash->to_current+size)%PAGE_SIZE > 0)))
	if(free_page_size < size)
	{
		printk("\r\nErase_page:address=%p\r\n", flash->to_current + (off_t) size - (flash->to_current + (off_t) size)%PAGE_SIZE - 0x78000);
		if (erase_page(flash, flash->to_current + (off_t) size)) {
			return -DELTA_CLEARING_ERROR;
		}
		flash->write_buf = 0;
	}

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	
	if (flash_write(flash->device, flash->to_current, buf_p, size)) {
		return -DELTA_WRITING_ERROR;
	}

	printk("\r\nFlash_write_to:address=0x%X\t size=%d\n", flash->to_current-0x78000,size);
	for(int i = 0; i< size; i++)
	{
		if(0 == i%16)
			printk("\r\n%p--%p:\t", flash->to_current-0x78000+i,flash->to_current+i);

		printk("%02X  ", buf_p[i]);
	}

	flash->to_current += (off_t) size;
	if (flash->to_current >= flash->to_end) {
		return -DELTA_SLOT1_OUT_OF_MEMORY;
	}

	return DELTA_OK;
}

static int delta_flash_from_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (flash_read(flash->device, flash->from_current, buf_p, size)) {
		return -DELTA_READING_SOURCE_ERROR;
	}

	flash->from_current += (off_t) size;
	if (flash->from_current >= flash->from_end) {
		return -DELTA_READING_SOURCE_ERROR;
	}

	return DELTA_OK;
}

static int delta_flash_patch_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (flash_read(flash->device, flash->patch_current, buf_p, size)) {
		return -DELTA_READING_PATCH_ERROR;
	}

	flash->patch_current += (off_t) size;
	if (flash->patch_current >= flash->patch_end) {
		return -DELTA_READING_PATCH_ERROR;
	}

	return DELTA_OK;
}

static int delta_flash_seek(void *arg_p, int offset)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}

	flash->from_current += offset;

	if (flash->from_current >= flash->from_end) {
		return -DELTA_SEEKING_ERROR;
	}

	return DELTA_OK;
}

/*
 *  INIT
 */

static int delta_init_flash_mem(struct flash_mem *flash)
{
	if (!flash) {
		return -DELTA_NO_FLASH_FOUND;
	}

	flash->from_current = PRIMARY_OFFSET;
	flash->from_end = flash->from_current + PRIMARY_SIZE;

	flash->to_current = SECONDARY_OFFSET;
	flash->to_end = flash->to_current + SECONDARY_SIZE;

	// flash->to_current = PRIMARY_OFFSET;
	// flash->to_end = flash->to_current + PRIMARY_SIZE;

	flash->patch_current = PATCH_OFFSET + HEADER_SIZE;
	flash->patch_end = flash->patch_current + PATCH_SIZE;

	flash->write_buf = 0;

	printf("\nfrom_current=%0X\t size=%0X\t to_current=%0X\t size=%0X\t patch_current=%0X\t size=%0X\n",
		flash->from_current,PRIMARY_SIZE,flash->to_current,SECONDARY_SIZE,flash->patch_current,PATCH_SIZE);

	return DELTA_OK;
}

static int delta_init(struct flash_mem *flash)
{
	int ret;

	ret = delta_init_flash_mem(flash);
	if (ret) {
		return ret;
	}
	ret = erase_page(flash, flash->to_current);
	if (ret) {
		return ret;
	}

	return DELTA_OK;
}

/*
 *  PUBLIC FUNCTIONS
 */

int delta_check_and_apply(struct flash_mem *flash)
{
	uint32_t patch_size; 
	int ret;

	ret = delta_read_patch_header(flash,&patch_size);
	printf("patch_size = %d\n", patch_size);
#if 1
	if (ret < 0) {
		printf("ret=%d	read patch file error, exit delta update process!!!\n", ret);
		return ret;
	} else if (patch_size > 0) {
		ret = delta_init(flash);
		if (ret) {
			return ret;
		}
		ret = detools_apply_patch_callbacks(delta_flash_from_read,
											delta_flash_seek,
											delta_flash_patch_read,
											(size_t) patch_size,
											delta_flash_write,
											flash);
		if (ret <= 0) {
			return ret;
		}
		//k_msleep(1000);		//for print debug message, added by Noy
		/** below code should be effect when release, now just for test */
		// if (boot_request_upgrade(BOOT_UPGRADE_PERMANENT)) {
		// return -1;
		// }
		// sys_reboot(SYS_REBOOT_COLD);
	}
	
#endif

	return DELTA_OK;
}

int delta_read_patch_header(struct flash_mem *flash, uint32_t *size)
{
	uint32_t new_patch, reset_msg, patch_header[2];
	static struct flash_pages_info page_info;

	new_patch = 0x5057454E; // ASCII for "NEWP" signaling new patch
	reset_msg = 0x0U; // reset "NEWP"

	/* For tests purposes use page (in primary_flash = 4 kB) */
	flash_get_page_info_by_offs(flash->device, PATCH_OFFSET,&page_info);
	printf("start_offset=%0X\t storage_size=%d\t size=%d\t index=%d\n",page_info.start_offset, PATCH_SIZE, page_info.size, page_info.index);

	if (flash_read(flash->device, PATCH_OFFSET, patch_header, sizeof(patch_header))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}
	printk("read_data[0]=%0X\t read_data[1]=%0X\r\n", patch_header[0], patch_header[1]);
	
	if (new_patch!=patch_header[0]) {
		*size = 0;
		return -DELTA_PATCH_HEADER_ERROR;
	}

	*size = patch_header[1];
	/** just for test */
	if (flash_write(flash->device, PATCH_OFFSET, &reset_msg, sizeof(reset_msg))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}

	return DELTA_OK;
}

const char *delta_error_as_string(int error)
{
	if (error < 28) {
		return detools_error_as_string(error);
	}

	if (error < 0) {
		error *= -1;
	}

	switch (error) {
	case DELTA_SLOT1_OUT_OF_MEMORY:
		return "Slot 1 out of memory.";
	case DELTA_READING_PATCH_ERROR:
		return "Error reading patch.";
	case DELTA_READING_SOURCE_ERROR:
		return "Error reading source image.";
	case DELTA_WRITING_ERROR:
		return "Error writing to slot 1.";
	case DELTA_SEEKING_ERROR:
		return "Seek error.";
	case DELTA_CASTING_ERROR:
		return "Error casting to flash_mem.";
	case DELTA_INVALID_BUF_SIZE:
		return "Read/write buffer less or equal to 0.";
	case DELTA_CLEARING_ERROR:
		return "Could not clear slot 1.";
	case DELTA_NO_FLASH_FOUND:
		return "No flash found.";
	case DELTA_PATCH_HEADER_ERROR:
		return "Error reading patch header.";
	default:
		return "Unknown error.";
	}
}
