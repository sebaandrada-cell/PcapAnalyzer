from __future__ import annotations


def conv_label(conv) -> str:
    return "%s:%d <-> %s:%d" % (conv.src, conv.src_port, conv.dst, conv.dst_port)
