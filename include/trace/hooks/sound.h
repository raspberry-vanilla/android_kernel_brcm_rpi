/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sound

#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_SOUND_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SOUND_H

#include <trace/hooks/vendor_hooks.h>

struct device;
struct device_node;

/*
 * Override the generated audio graph DAI link name. The endpoint is the
 * CPU endpoint for a DPCM FE, or the codec endpoint for other links.
 * A replacement name must remain valid for the lifetime of the card.
 */
DECLARE_HOOK(android_vh_audio_graph_dai_link_name,
	TP_PROTO(struct device *dev, struct device_node *ep, const char **name),
	TP_ARGS(dev, ep, name));

/*
 * This hook allows the vendor driver to tell the kernel:
 * "Don't allocate a buffer for this stream."
 */
struct snd_pcm_substream;

DECLARE_HOOK(android_vh_snd_pcm_check_no_buffer,
	TP_PROTO(struct snd_pcm_substream *substream, bool *no_buffer),
	TP_ARGS(substream, no_buffer));

#endif /* _TRACE_HOOK_SOUND_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
