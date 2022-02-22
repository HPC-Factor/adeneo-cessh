//-------------------------------------------------------------------------
// <copyright file="abort.h" company="Adeneo">
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//    The use and distribution terms for this software are covered by the
//    Limited Permissive License (Ms-LPL) 
//    which can be found in the file LPL.txt at the root of this distribution.
//    By using this software in any fashion, you are agreeing to be bound by
//    the terms of this license.
//
//    The software is licensed "as-is."
//
//    You must not remove this notice, or any other, from this software.
// </copyright> 
//-------------------------------------------------------------------------
#ifndef __ABORT_H__
#define __ABORT_H__


#ifdef __cplusplus
extern "C" {
#endif


void __abort(char*,int);
#define abort() __abort(__FILE__,__LINE__)



#ifdef __cplusplus
}
#endif

#endif
