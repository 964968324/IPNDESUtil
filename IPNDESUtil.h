//
//  IPNDESUtil.h
//  TestPlugin
//
//  Created by 刘宁 on 14/11/26.
//  Copyright (c) 2014年 Ipaynow. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CommonCryptor.h"
#import "IPNGTMBase64.h"


@interface IPNDESUtil : NSObject

+ (NSString*) md5Encrypt: (NSString *) inPutText;
+(NSString *)TripleDESDecrypt:(NSString *)plainText WithKey:(NSString *)keyStr;
+(NSString *)TripleDESDecrypt:(NSString *)plainText WithKey:(NSString *)keyStr;

+ (NSData *)dataFromHexString:(NSString *)hexString;
+ (NSString *)hexStringFromString:(NSData *)data;
+(NSString *) sortString:(NSString *) inputText;

@end
