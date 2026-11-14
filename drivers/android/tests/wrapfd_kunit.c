// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for the wrapfd driver.
 *
 * Copyright (C) 2026, Google LLC.
 * Author: Suren Baghdasaryan <surenb@google.com>
 */
#include <kunit/device.h>
#include <kunit/test.h>

#include <linux/dma-buf.h>
#include <linux/fdtable.h>
#include <linux/mman.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wrapfd.h>

#include "../wrapfd_internal.h"

struct test_buffer {
	struct page *page;
	size_t size;
	struct sg_table sgt;
};

static struct sg_table *test_map_dmabuf(struct dma_buf_attachment *attach,
		enum dma_data_direction direction)
{
	struct test_buffer *priv = attach->dmabuf->priv;

	return &priv->sgt;
}

static void test_unmap_dmabuf(struct dma_buf_attachment *attach,
		struct sg_table *sgt, enum dma_data_direction direction)
{
	/* No-op for dummy testing memory */
}

static void test_release(struct dma_buf *dmabuf)
{
	struct test_buffer *priv = dmabuf->priv;

	sg_free_table(&priv->sgt);
	__free_page(priv->page);
	kfree(priv);
}

/* Minimal operations table required by dma_buf_export() */
static const struct dma_buf_ops test_dmabuf_ops = {
	.map_dma_buf   = test_map_dmabuf,
	.unmap_dma_buf = test_unmap_dmabuf,
	.release       = test_release,
};

static struct dma_buf *create_test_dmabuf(void)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct test_buffer *priv;
	struct dma_buf *dmabuf;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	priv->page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!priv->page) {
		kfree(priv);
		return ERR_PTR(-ENOMEM);
	}

	ret = sg_alloc_table_from_pages(&priv->sgt, &priv->page,
					1, 0, PAGE_SIZE, GFP_KERNEL);
	if (ret) {
		__free_page(priv->page);
		kfree(priv);
		return ERR_PTR(ret);
	}

	exp_info.ops = &test_dmabuf_ops;
	exp_info.size = PAGE_SIZE;
	exp_info.flags = O_RDWR;
	exp_info.priv = priv;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		sg_free_table(&priv->sgt);
		__free_page(priv->page);
		kfree(priv);
	}

	return dmabuf;
}

static struct test_data {
	struct device *mock_dev1;
	struct device *mock_dev2;
	struct dma_buf *dmabuf;
	int empty_wrapfd;
	int wrapfd;
	bool emptied;
	struct file *file;
	struct file *empty_file;
} test_data;

static int wrapfd_suite_init(struct kunit_suite *suite)
{
	struct dma_buf *dmabuf;
	int empty_wrapfd;
	int dmabuf_fd;
	int wrapfd;
	int err;

	memset(&test_data, 0, sizeof(test_data));

	dmabuf = create_test_dmabuf();
	if (IS_ERR(dmabuf)) {
		err = PTR_ERR(dmabuf);
		pr_err("Failed to create DMA-BUF: %d\n", err);
		return err;
	}

	dmabuf_fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (dmabuf_fd < 0) {
		err = dmabuf_fd;
		pr_err("Failed to install dmabuf fd: %d\n", err);
		dma_buf_put(dmabuf);
		return err;
	}

	/*
	 * Can't empty now because device to take the ownership is not ready yet.
	 * Will do that after devices are initialized in wrapfd_test_init().
	 */
	empty_wrapfd = create_wrapfd(dmabuf_fd, PROT_READ | PROT_WRITE);
	if (empty_wrapfd < 0) {
		err = empty_wrapfd;
		pr_err("Failed to create wrapfd: %d\n", err);
		goto close_dmabuf;
	}

	wrapfd = create_wrapfd(dmabuf_fd, PROT_READ | PROT_WRITE);
	if (wrapfd < 0) {
		err = wrapfd;
		pr_err("Failed to create wrapfd: %d\n", err);
		goto close_empty_wrapfd;
	}
	close_fd(dmabuf_fd);

	test_data.dmabuf = dmabuf;
	test_data.wrapfd = wrapfd;
	test_data.empty_wrapfd = empty_wrapfd;
	test_data.file = fget(wrapfd);
	test_data.empty_file = fget(empty_wrapfd);

	return 0;
close_empty_wrapfd:
	close_fd(empty_wrapfd);
close_dmabuf:
	close_fd(dmabuf_fd);

	return err;
}

static void wrapfd_suite_exit(struct kunit_suite *suite)
{
	if (!test_data.dmabuf)
		return;

	close_fd(test_data.empty_wrapfd);
	fput(test_data.file);

	close_fd(test_data.wrapfd);
	fput(test_data.empty_file);
}

static int wrapfd_test_init(struct kunit *test)
{
	struct device *dev1;
	struct device *dev2;

	if (!test_data.dmabuf)
		kunit_skip(test, "DMA-BUF was not created");

	dev1 = kunit_device_register(test, "mock_device1");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dev1);
	test_data.mock_dev1 = dev1;

	dev2 = kunit_device_register(test, "mock_device2");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dev2);
	test_data.mock_dev2 = dev2;

	if (!test_data.emptied) {
		KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(test_data.empty_file, dev1), 0);
		KUNIT_ASSERT_EQ(test, empty_wrapfd(test_data.empty_file, dev1), 0);
		KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(test_data.empty_file, dev1), 0);
		test_data.emptied = true;
	}

	return 0;
}

static void wrapfd_test_exit(struct kunit *test)
{
	if (test_data.mock_dev2) {
		kunit_device_unregister(test, test_data.mock_dev2);
		test_data.mock_dev2 = NULL;
	}
	if (test_data.mock_dev1) {
		kunit_device_unregister(test, test_data.mock_dev1);
		test_data.mock_dev1 = NULL;
	}
}

static void wrapfd_get_mappable_test(struct kunit *test)
{
	struct device *dev1 = test_data.mock_dev1;
	struct device *dev2 = test_data.mock_dev2;
	union wrapfd_mappable mappable;
	struct file *empty_file;
	struct file *file;

	empty_file = test_data.empty_file;
	file = test_data.file;

	/* Test invalid inputs */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(NULL, dev1, &mappable), -EBADF);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(NULL, dev1, &mappable), -EBADF);
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, NULL, &mappable), -ENODEV);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, NULL, &mappable), -ENODEV);
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, NULL), -EINVAL);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev1, NULL), -EINVAL);

	/* Get mappable object when no owners and no other users */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev1, &mappable), 0);

	/* Get mappable object with other users */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev2, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev2, &mappable), 0);

	/* Get mappable object while being the owner */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev1), 0);

	/* Get mappable object while someone else is the owner */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev2), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, &mappable), -EBUSY);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev2), 0);

	/* Get mappable object of an empty buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(empty_file, dev1, &mappable),
					-ENOENT);
}

static void wrapfd_acquire_ownership_test(struct kunit *test)
{
	struct device *dev1 = test_data.mock_dev1;
	struct device *dev2 = test_data.mock_dev2;
	union wrapfd_mappable mappable;
	struct file *empty_file;
	struct file *file;

	empty_file = test_data.empty_file;
	file = test_data.file;

	/* Test invalid inputs */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(NULL, dev1), -EBADF);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(NULL, dev1), -EBADF);
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, NULL), -ENODEV);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, NULL), -ENODEV);

	/* Get ownership when no owners and no other users */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev1), 0);

	/* Get ownership while owning the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev1), 0);

	/* Get ownership while someone else owns the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev2), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), -EBUSY);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev2), 0);

	/* Get ownership while mapping the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev1, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), -EINVAL);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev1, &mappable), 0);

	/* Get ownership while someone else maps the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_get_mappable(file, dev2, &mappable), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev1), -EINVAL);
	KUNIT_ASSERT_EQ(test, wrapfd_put_mappable(file, dev2, &mappable), 0);

	/* Put ownership when nobody owns the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev1), -EBUSY);

	/* Put ownership when someone else owns the buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(file, dev2), 0);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev1), -EBUSY);
	KUNIT_ASSERT_EQ(test, wrapfd_release_ownership(file, dev2), 0);

	/* Get ownership of an empty buffer */
	KUNIT_ASSERT_EQ(test, wrapfd_acquire_ownership(empty_file, dev2), -ENOENT);
}

static struct kunit_case wrapfd_test_cases[] = {
	KUNIT_CASE(wrapfd_get_mappable_test),
	KUNIT_CASE(wrapfd_acquire_ownership_test),
	{},
};

static struct kunit_suite wrapfd_test_module = {
	.name = "wrapfd",
	.init = wrapfd_test_init,
	.exit = wrapfd_test_exit,
	.suite_init = wrapfd_suite_init,
	.suite_exit = wrapfd_suite_exit,
	.test_cases = wrapfd_test_cases,
};

kunit_test_suites(&wrapfd_test_module);

MODULE_DESCRIPTION("KUnit test for the wrapfd driver");
MODULE_IMPORT_NS(DMA_BUF);
MODULE_LICENSE("GPL");
