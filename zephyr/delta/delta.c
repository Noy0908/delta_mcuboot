/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "delta.h"

#define DATA_LEN 2
#define ADDR_LEN 4
#define DATA_HEADER (DATA_LEN+ADDR_LEN)
#define MAGIC_VALUE1 0x202215FF
#define MAGIC_VALUE2 0x202215F0
#define MAGIC_VALUE3 0x20221500
#define ERASE_PAGE_SIZE (PAGE_SIZE*2)
#define IMAGE_ARRAY_SIZE PAGE_SIZE/8
#define MAX_WRITE_UNIT 128  //relating to to/from array of process_data in detools.c

volatile int erased_addr;
volatile bool real_apply;
uint32_t patch_size; 
bool is_init;

struct
{
	int addr[IMAGE_ARRAY_SIZE];
	uint16_t size[IMAGE_ARRAY_SIZE];
	uint16_t count;
} image_position_adjust;


static int delta_flash_write(void *arg_p,
					const uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;
	static uint8_t to_flash_buf[ERASE_PAGE_SIZE + MAX_WRITE_UNIT];
	uint16_t i;

	flash = (struct flash_mem *)arg_p;	

	printk("to_flash write size 0x%x\r", size);

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}

	if (!real_apply)
	{		
		flash->write_buf += size;
		if (flash->write_buf >= ERASE_PAGE_SIZE) {
			erased_addr =  flash->to_current + ERASE_PAGE_SIZE;
			printk("==== erased_addr 0x%x\r", erased_addr);
			flash->to_current += (off_t) ERASE_PAGE_SIZE;
			flash->write_buf = flash->write_buf - ERASE_PAGE_SIZE;
		}

		if (flash->flush_write)
		{
			uint32_t total_size = 0;
			uint8_t data[MAX_WRITE_UNIT + DATA_HEADER + 2];
			uint32_t addr;
			uint32_t magic[2];

			magic[0] = MAGIC_VALUE1;

			printk("==== Write adjustment to Flash\r");
			//write image_position_adjust to Flash
			for (i = 0; i < image_position_adjust.count; i++)
			{
				total_size += (DATA_HEADER +image_position_adjust.size[i]);  //addr->4bytes len->2bytes				
			}
			printk("==== totat size 0x%x\r", total_size);

			if ((patch_size + HEADER_SIZE + total_size) > SECONDARY_SIZE)
			{
				printk("## The delta file has a big variation!");
				return DELTA_WRITING_ERROR;
			}

			for (i = 1; i <= (total_size/PAGE_SIZE + 1); i++)
			{
				flash_erase(flash->device, flash->patch_end - i * PAGE_SIZE, PAGE_SIZE);
			}			
			magic[1] = addr = flash->patch_end - PAGE_SIZE * (i-1);

			for (i = 0; i < image_position_adjust.count; i++)
			{				
				total_size = (DATA_HEADER +image_position_adjust.size[i]);
				*(uint16_t *)&data[0] = image_position_adjust.size[i];
				*(uint32_t *)&data[DATA_LEN] = image_position_adjust.addr[i];

				if (flash_read(flash->device, image_position_adjust.addr[i], &data[DATA_HEADER], 
					image_position_adjust.size[i]))
				{
					printk("flash read err\r");
					return -DELTA_READING_SOURCE_ERROR;
				}

				if (flash_write(flash->device, addr, data, total_size)) {
					printk("flash write err\r");
					return -DELTA_WRITING_ERROR;
				}

				addr += total_size;
			}

			if (flash_write(flash->device, flash->patch_end-sizeof(magic), magic, sizeof(magic))) {
				printk("magic1 write err\r");
				return -DELTA_WRITING_ERROR;
			}			
		}

		return DELTA_OK;		
	}

	if (flash->flush_write)
	{
		printk("===== Flush last Flash buffer\r");
		if (flash_erase(flash->device, flash->to_current, ERASE_PAGE_SIZE)) {
			return -DELTA_CLEARING_ERROR;
		}
		if (flash_write(flash->device, flash->to_current, to_flash_buf, flash->write_buf)) {
			printk("flash write err\r");
			return -DELTA_WRITING_ERROR;
		}

		flash->to_current += flash->write_buf;
		flash->write_buf = 0;
		flash->flush_write = false;
		
		return DELTA_OK;		
	}

	if (size > PAGE_SIZE)
	{
		printk("error size\r");
		return -DELTA_WRITING_ERROR;
	}
	// if (flash_write_protection_set(flash->device, false)) {
	// 	return -DELTA_WRITING_ERROR;
	// }

	memcpy(to_flash_buf + flash->write_buf, buf_p, size);  //put the TO content to a temp buffer first
	flash->write_buf += size;

	if (flash->write_buf >= ERASE_PAGE_SIZE) {
		if (flash_erase(flash->device, flash->to_current, ERASE_PAGE_SIZE)) {
			return -DELTA_CLEARING_ERROR;
		}

		erased_addr =  flash->to_current + ERASE_PAGE_SIZE;

		if (flash_write(flash->device, flash->to_current, to_flash_buf, ERASE_PAGE_SIZE)) {
			printk("flash write2 err\r");
			return -DELTA_WRITING_ERROR;
		}
		flash->to_current += (off_t) ERASE_PAGE_SIZE;
		if (flash->to_current >= flash->to_end) {
			return -DELTA_SLOT1_OUT_OF_MEMORY;
		}

		flash->write_buf = flash->write_buf - ERASE_PAGE_SIZE;			
		memcpy(to_flash_buf, &to_flash_buf[ERASE_PAGE_SIZE], flash->write_buf);		
		
	}

	return DELTA_OK;
}


int write_last_buffer(void *arg_p)
{
	struct flash_mem *flash;
	uint8_t temp[4];

	flash = (struct flash_mem *)arg_p;
	flash->flush_write = true;

	return delta_flash_write(arg_p, temp, 4);
	
}

static int delta_flash_from_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;
	static int fatal_err = 0;

	flash = (struct flash_mem *)arg_p;

	printk("from_flash read size: 0x%x off: 0x%x\r", size, flash->from_current);

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (fatal_err)
	{
		return -DELTA_CASTING_ERROR;
	}

	if (flash->from_current < erased_addr)
	{
		if (!real_apply)
		{
			printk("=== adjust pos %d\r", image_position_adjust.count);
			image_position_adjust.addr[image_position_adjust.count] = flash->from_current;
			image_position_adjust.size[image_position_adjust.count] = size;
			image_position_adjust.count++;
			if (image_position_adjust.count > IMAGE_ARRAY_SIZE)
			{
				fatal_err = -DELTA_WRITING_ERROR;
				return -DELTA_WRITING_ERROR;				
			}
		}
		else
		{			
			static uint32_t addr;
			uint32_t magic[2];
			uint8_t data[DATA_HEADER];

			if (is_init)
			{
				fatal_err = 0;
				if (flash_read(flash->device, flash->patch_end-8, magic, 8)) {
					fatal_err = -DELTA_READING_SOURCE_ERROR;
					return -DELTA_READING_SOURCE_ERROR;
				}
				if (magic[0] == MAGIC_VALUE1)
				{
					magic[0] = MAGIC_VALUE2;
					if (flash_write(flash->device, flash->patch_end-8, magic, 4)) {
						printk("magic2 write err\r");
						fatal_err = -DELTA_WRITING_ERROR;
						return -DELTA_WRITING_ERROR;
					}					
				}
				else if (magic[0] != MAGIC_VALUE2)
				{
					fatal_err = -DELTA_SEEKING_ERROR;
					return -DELTA_SEEKING_ERROR;
				}				
				addr = magic[1];
				printk("## image adjust start addr 0x%x\r", addr);	 
			}

			if (flash_read(flash->device, addr, data, sizeof(data))) {
				fatal_err = -DELTA_READING_SOURCE_ERROR;
				return -DELTA_READING_SOURCE_ERROR;
			}
			addr += DATA_HEADER;

			if ((*(uint16_t*)&data[0]) != size ||
					(*(uint32_t*)&data[DATA_LEN]) != flash->from_current)
			{
				printk("address or size mismatch!\r");
				fatal_err = -DELTA_READING_SOURCE_ERROR;
				return -DELTA_READING_SOURCE_ERROR;
			}

			if (flash_read(flash->device, addr, buf_p, size)) {
				fatal_err = -DELTA_READING_SOURCE_ERROR;
				return -DELTA_READING_SOURCE_ERROR;
			}
			addr += size;
			is_init = false;
		}		
	}
	else
	{
		if (flash_read(flash->device, flash->from_current, buf_p, size)) {
			return -DELTA_READING_SOURCE_ERROR;
		}
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
	printk("patch_flash read size 0x%x\r", size);

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

	printk("from_flash seek offset %d\r", offset);
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

	flash->from_current = PRIMARY_OFFSET + PAGE_SIZE;
	flash->from_end = flash->from_current + PRIMARY_SIZE - PAGE_SIZE;

	flash->to_current = PRIMARY_OFFSET;
	flash->to_end = flash->to_current + PRIMARY_SIZE - PAGE_SIZE;

	erased_addr = PRIMARY_OFFSET;

	flash->patch_current = SECONDARY_OFFSET + 0x200 + HEADER_SIZE;
	flash->patch_end = flash->patch_current + SECONDARY_SIZE - HEADER_SIZE - 0x200 - PAGE_SIZE;

	flash->write_buf = 0;
	flash->flush_write = false;

	image_position_adjust.count = 0;
	is_init = true;

	printf("\nfrom_current=0x%X\t size=0x%X\t to_current=0x%X\t size=0x%X\t patch_current=0x%X\t size=0x%X\n",
		flash->from_current,PRIMARY_SIZE,flash->to_current,SECONDARY_SIZE,flash->patch_current,STORAGE_SIZE);
	
	return DELTA_OK;
}

static int delta_init(struct flash_mem *flash)
{
	int ret;

	ret = delta_init_flash_mem(flash);
	if (ret) {
		return ret;
	}

	return DELTA_OK;
}

bool enter_delta_dfu(struct flash_mem *flash)
{
	int ret;

	ret = delta_read_patch_header(flash,&patch_size);
	if (ret < 0) {		
		return false;
	} else if (patch_size > 0) {
		return true;
	}		
}

/*
 *  PUBLIC FUNCTIONS
 */

int delta_check_and_apply(struct flash_mem *flash)
{
	int ret;

	ret = delta_read_patch_header(flash,&patch_size);
	printf("##patch_size = %d\n", patch_size);
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
	// static struct flash_pages_info page_info;

	new_patch = 0x5057454E; // ASCII for "NEWP" signaling new patch
	reset_msg = 0x0U; // reset "NEWP"

	/* For tests purposes use page (in primary_flash = 4 kB) */
	// flash_get_page_info_by_offs(flash->device, STORAGE_OFFSET,&page_info);
	// printf("start_offset=%0X\t storage_size=%d\t size=%d\t index=%d\n",page_info.start_offset, STORAGE_SIZE, page_info.size, page_info.index);

	if (flash_read(flash->device, SECONDARY_OFFSET + 0x200, patch_header, sizeof(patch_header))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}
	printk("read_data[0]=%0X\t read_data[1]=%0X\r\n", patch_header[0], patch_header[1]);
	
	if (new_patch!=patch_header[0]) {
		*size = 0;
		return -DELTA_PATCH_HEADER_ERROR;
	}

	*size = patch_header[1];
	/** just for test */
	if (real_apply)
	{
		if (flash_write(flash->device, SECONDARY_OFFSET + 0x200, &reset_msg, sizeof(reset_msg))) {
			return -DELTA_PATCH_HEADER_ERROR;
		}
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
