#*********************************************************************************************************
#
#                                 北京翼辉信息技术有限公司
#
#                                   微型安全实时操作系统
#
#                                       MS-RTOS(TM)
#
#                               Copyright All Rights Reserved
#
#--------------文件信息--------------------------------------------------------------------------------
#
# 文   件   名: libcoap.mk
#
# 创   建   人: IoT Studio
#
# 文件创建日期: 2020 年 02 月 13 日
#
# 描        述: 本文件由 IoT Studio 生成，用于配置 Makefile 功能，请勿手动修改
#*********************************************************************************************************

#*********************************************************************************************************
# Clear setting
#*********************************************************************************************************
include $(CLEAR_VARS_MK)

#*********************************************************************************************************
# Target
#*********************************************************************************************************
LOCAL_TARGET_NAME := libcoap.a

#*********************************************************************************************************
# Source list
#*********************************************************************************************************
LOCAL_SRCS :=  \
src/libcoap/src/address.c \
src/libcoap/src/async.c \
src/libcoap/src/block.c \
src/libcoap/src/coap_debug.c \
src/libcoap/src/coap_event.c \
src/libcoap/src/coap_gnutls.c \
src/libcoap/src/coap_hashkey.c \
src/libcoap/src/coap_io.c \
src/libcoap/src/coap_mbedtls.c \
src/libcoap/src/coap_notls.c \
src/libcoap/src/coap_openssl.c \
src/libcoap/src/coap_session.c \
src/libcoap/src/coap_tcp.c \
src/libcoap/src/coap_time.c \
src/libcoap/src/coap_tinydtls.c \
src/libcoap/src/encode.c \
src/libcoap/src/mem.c \
src/libcoap/src/net.c \
src/libcoap/src/option.c \
src/libcoap/src/pdu.c \
src/libcoap/src/resource.c \
src/libcoap/src/str.c \
src/libcoap/src/subscribe.c \
src/libcoap/src/uri.c \

#*********************************************************************************************************
# Header file search path (eg. LOCAL_INC_PATH := -I"Your header files search path")
#*********************************************************************************************************
LOCAL_INC_PATH := \
-I"./src" \
-I"./src/libcoap/include/coap2"

#*********************************************************************************************************
# Pre-defined macro (eg. -DYOUR_MARCO=1)
#*********************************************************************************************************
LOCAL_DSYMBOL := 

#*********************************************************************************************************
# Compiler flags
#*********************************************************************************************************
LOCAL_CFLAGS   := 
LOCAL_CXXFLAGS := 

#*********************************************************************************************************
# Depend library (eg. LOCAL_DEPEND_LIB := -la LOCAL_DEPEND_LIB_PATH := -L"Your library search path")
#*********************************************************************************************************
LOCAL_DEPEND_LIB      := 
LOCAL_DEPEND_LIB_PATH := 

#*********************************************************************************************************
# C++ config
#*********************************************************************************************************
LOCAL_USE_CXX        := no
LOCAL_USE_CXX_EXCEPT := no

#*********************************************************************************************************
# Code coverage config
#*********************************************************************************************************
LOCAL_USE_GCOV := no

#*********************************************************************************************************
# Stack check config
#*********************************************************************************************************
LOCAL_USE_STACK_CHECK := no

#*********************************************************************************************************
# User link command
#*********************************************************************************************************
LOCAL_PRE_LINK_CMD   := 
LOCAL_POST_LINK_CMD  := 
LOCAL_PRE_STRIP_CMD  := 
LOCAL_POST_STRIP_CMD := 

#*********************************************************************************************************
# Depend target
#*********************************************************************************************************
LOCAL_DEPEND_TARGET := 

include $(STATIC_LIBRARY_MK)

#*********************************************************************************************************
# End
#*********************************************************************************************************
