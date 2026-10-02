// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2021 Google LLC
 *
 * This file can optionally be built into fips140.ko in order to support certain
 * types of testing that the FIPS lab has to do to evaluate the module.  It
 * should not be included in production builds of the module.
 */

/*
 * We have to redefine inline to mean always_inline, so that _copy_to_user()
 * gets inlined.  This is needed for it to be placed into the correct section.
 * See fips140_copy_to_user().
 *
 * We also need to undefine BUILD_FIPS140_KO to allow the use of the code
 * patching which copy_to_user() requires.
 */
#undef inline
#define inline inline __attribute__((__always_inline__)) __gnu_inline \
       __inline_maybe_unused notrace
#undef BUILD_FIPS140_KO

/*
 * Since this .c file contains real module parameters for fips140.ko, it needs
 * to be compiled normally, so undo the hacks that were done in fips140-defs.h.
 */
#define MODULE
#undef KBUILD_MODFILE
#undef __DISABLE_EXPORTS

#include <crypto/aes.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "fips140-module.h"
#include "fips140-eval-testing-uapi.h"

/*
 * This option allows deliberately failing the self-tests for a particular
 * algorithm.
 */
static char *fips140_fail_selftest;
module_param_named(fail_selftest, fips140_fail_selftest, charp, 0);

/* This option allows deliberately failing the integrity check. */
static bool fips140_fail_integrity_check;
module_param_named(fail_integrity_check, fips140_fail_integrity_check, bool, 0);

static dev_t fips140_devnum;
static struct cdev fips140_cdev;

/* Inject a self-test failure (via corrupting the result) if requested. */
void fips140_inject_selftest_failure(const char *impl, u8 *result)
{
	if (fips140_fail_selftest && strcmp(impl, fips140_fail_selftest) == 0)
		result[0] ^= 0xff;
}

/* Inject an integrity check failure (via corrupting the text) if requested. */
void fips140_inject_integrity_failure(u8 *textcopy)
{
	if (fips140_fail_integrity_check)
		textcopy[0] ^= 0xff;
}

static long fips140_ioctl_is_approved_service(unsigned long arg)
{
	const char *service_name = strndup_user((const char __user *)arg, 256);
	long ret;

	if (IS_ERR(service_name))
		return PTR_ERR(service_name);

	ret = fips140_is_approved_service(service_name);

	kfree(service_name);
	return ret;
}

/*
 * Code in fips140.ko is covered by an integrity check by default, and this
 * check breaks if copy_to_user() is called.  This is because copy_to_user() is
 * an inline function that relies on code patching.  However, since this is
 * "evaluation testing" code which isn't included in the production builds of
 * fips140.ko, it's acceptable to just exclude it from the integrity check.
 */
static noinline unsigned long __section("text.._fips140_unchecked")
fips140_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return copy_to_user(to, from, n);
}

static long fips140_ioctl_module_version(unsigned long arg)
{
	const char *version = fips140_module_version();
	size_t len = strlen(version) + 1;

	if (len > 256)
		return -EOVERFLOW;

	if (fips140_copy_to_user((void __user *)arg, version, len))
		return -EFAULT;

	return 0;
}

static void fips140_begin_zeroization_test(const char *test_name,
					   const void *data, size_t len)
{
	pr_info("Testing %s zeroization...\n", test_name);
	print_hex_dump(KERN_INFO, "BEFORE: ", DUMP_PREFIX_OFFSET, 16, 1, data,
		       len, true);
	WARN_ON_ONCE(mem_is_zero(data, len));
}

static __must_check bool fips140_end_zeroization_test(const char *test_name,
						      const void *data,
						      size_t len)
{
	pr_info("Executed %s zeroization\n", test_name);
	print_hex_dump(KERN_INFO, "AFTER:  ", DUMP_PREFIX_OFFSET, 16, 1, data,
		       len, true);
	if (!mem_is_zero(data, len)) {
		pr_err("%s zeroization test failed!\n", test_name);
		return false;
	}
	pr_info("%s zeroization test passed.\n", test_name);
	return true;
}

static noinline_for_stack bool fips140_test_zeroization_raw(void)
{
	u8 data[32];

	get_random_bytes(data, sizeof(data));
	fips140_begin_zeroization_test("memzero_explicit", data, sizeof(data));
	memzero_explicit(data, sizeof(data));
	return fips140_end_zeroization_test("memzero_explicit", data,
					    sizeof(data));
}

static noinline_for_stack bool fips140_test_zeroization_aes(void)
{
	u8 raw_key[AES_KEYSIZE_256];
	struct crypto_aes_ctx aes_key;
	int err;

	get_random_bytes(raw_key, sizeof(raw_key));
	err = aes_expandkey(&aes_key, raw_key, sizeof(raw_key));
	memzero_explicit(raw_key, sizeof(raw_key));
	if (err) {
		pr_err("AES key preparation failed\n");
		return false;
	}
	fips140_begin_zeroization_test("AES key", &aes_key, sizeof(aes_key));
	memzero_explicit(&aes_key, sizeof(aes_key));
	return fips140_end_zeroization_test("AES key", &aes_key,
					    sizeof(aes_key));
}

static noinline_for_stack bool fips140_test_zeroization_hmac_sha512(void)
{
	struct crypto_shash *tfm;
	u8 raw_key[32];
	u8 data[SHA512_BLOCK_SIZE];
	u8 mac[SHA512_DIGEST_SIZE];
	int err;

	tfm = crypto_alloc_shash("hmac(sha512)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("failed to allocate hmac tfm (%ld)\n", PTR_ERR(tfm));
		return false;
	}

	get_random_bytes(raw_key, sizeof(raw_key));
	err = crypto_shash_setkey(tfm, raw_key, sizeof(raw_key));
	memzero_explicit(raw_key, sizeof(raw_key));
	if (err) {
		pr_err("HMAC key preparation failed\n");
		crypto_free_shash(tfm);
		return false;
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		const size_t descsize = crypto_shash_descsize(tfm);
		bool ok;

		desc->tfm = tfm;
		crypto_shash_init(desc);
		get_random_bytes(data, sizeof(data));
		crypto_shash_update(desc, data, sizeof(data));
		fips140_begin_zeroization_test("HMAC-SHA512 context",
					       shash_desc_ctx(desc), descsize);
		crypto_shash_final(desc, mac);
		shash_desc_zero(desc);
		ok = fips140_end_zeroization_test("HMAC-SHA512 context",
						  shash_desc_ctx(desc),
						  descsize);
		crypto_free_shash(tfm);
		return ok;
	}
}

/* Run zeroization tests for selected cases. */
static int fips140_ioctl_test_zeroization(void)
{
	bool ok = true;

	ok &= fips140_test_zeroization_raw();
	ok &= fips140_test_zeroization_aes();
	ok &= fips140_test_zeroization_hmac_sha512();
	return ok ? 1 : 0;
}

static long fips140_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	switch (cmd) {
	case FIPS140_IOCTL_IS_APPROVED_SERVICE:
		return fips140_ioctl_is_approved_service(arg);
	case FIPS140_IOCTL_MODULE_VERSION:
		return fips140_ioctl_module_version(arg);
	case FIPS140_IOCTL_TEST_ZEROIZATION:
		return fips140_ioctl_test_zeroization();
	default:
		return -ENOTTY;
	}
}

static const struct file_operations fips140_fops = {
	.unlocked_ioctl = fips140_ioctl,
};

bool fips140_eval_testing_init(void)
{
	if (alloc_chrdev_region(&fips140_devnum, 1, 1, "fips140") != 0) {
		pr_err("failed to allocate device number\n");
		return false;
	}
	cdev_init(&fips140_cdev, &fips140_fops);
	if (cdev_add(&fips140_cdev, fips140_devnum, 1) != 0) {
		pr_err("failed to add fips140 character device\n");
		return false;
	}
	return true;
}
