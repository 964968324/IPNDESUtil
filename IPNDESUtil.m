//
//  IPNDESUtil.m
//  TestPlugin
//
//  Created by 刘宁 on 14/11/26.
//  Copyright (c) 2014年 Ipaynow. All rights reserved.
//

#import "IPNDESUtil.h"
#import "CommonDigest.h"

@implementation IPNDESUtil

+(NSString *)TripleDESEncrypt:(NSString *)plainText WithKey:(NSString *)keyStr{
    NSData *kd=[keyStr dataUsingEncoding:NSUTF8StringEncoding];
    const void *key=kd.bytes;
    
    NSData *dt=[plainText dataUsingEncoding:NSUTF8StringEncoding];
    const void *data=dt.bytes;
    int dataLength = (int)dt.length;
    
    int diff = 8 - (dataLength % 8);
    int newSize = 0;
    if(diff > 0)
        newSize = dataLength + diff;
    
    char dataPtr[newSize];
    memcpy(dataPtr, data, dataLength);
    for(int i = 0; i < diff; i++){
        dataPtr[i + dataLength] = 0x00;
    }
    
    void *buffer;
    buffer = malloc( newSize * sizeof(uint8_t));
    memset(buffer, 0x0, newSize);  //补零
    memcpy(buffer, data, dataLength);      //复制
    
    void *k;
    k=malloc(24*sizeof(uint8_t));
    memcpy(k, key, 24);
    size_t movedBytes = 0;
    CCCryptorStatus ccStatus=  CCCrypt(kCCEncrypt,
                                       kCCAlgorithm3DES,
                                       kCCOptionECBMode|kCCOptionPKCSNoPadding,
                                       k,
                                       kCCKeySize3DES,
                                       nil,
                                       dataPtr,
                                       newSize,
                                       buffer,
                                       newSize,
                                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const void *)buffer length:(NSUInteger)movedBytes];
    NSString *ret=[IPNGTMBase64 encodeBase64Data:myData];
    return ret;
}


+(NSString *)TripleDESDecrypt:(NSString *)plainText WithKey:(NSString *)keyStr{
    NSData *kd=[keyStr dataUsingEncoding:NSUTF8StringEncoding];
    const void *key=kd.bytes;
    
    NSData *dt=[IPNGTMBase64 decodeString:plainText];
    const void *data=dt.bytes;
    long dataLength = dt.length;
    
    void *buffer;
    buffer = malloc( dataLength * sizeof(uint8_t));
    memcpy(buffer, data, dataLength);      //复制
    
    void *k;
    k=malloc(24*sizeof(uint8_t));
    memcpy(k, key, 24);
    size_t movedBytes = 0;
    CCCryptorStatus ccStatus =  CCCrypt(kCCDecrypt,
                                       kCCAlgorithm3DES,
                                       kCCOptionECBMode|kCCOptionPKCSNoPadding,
                                       k,
                                       kCCKeySize3DES,
                                       nil,
                                       data,
                                       dataLength,
                                       buffer,
                                       dataLength,
                                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const void *)buffer length:(NSUInteger)movedBytes];
    NSString *ret=[[NSString alloc]initWithData:myData encoding:NSUTF8StringEncoding];
    return ret;
}


+ (NSData *)dataFromHexString:(NSString *)hexString { //
    char *myBuffer = (char *)malloc((int)[hexString length] / 2 + 1);
    bzero(myBuffer, [hexString length] / 2 + 1);
    for (int i = 0; i < [hexString length] - 1; i += 2) {
        unsigned int anInt;
        NSString * hexCharStr = [hexString substringWithRange:NSMakeRange(i, 2)];
        NSScanner * scanner = [[NSScanner alloc] initWithString:hexCharStr] ;
        [scanner scanHexInt:&anInt];
        myBuffer[i / 2] = (char)anInt;
    }
    NSData *myData=[NSData dataWithBytes:myBuffer length:(int)[hexString length] / 2 + 1];
    return myData;
}

+ (NSString *)hexStringFromString:(NSData *)data{
    Byte *bytes = (Byte *)[data bytes];
    //下面是Byte 转换为16进制。
    NSString *hexStr=@"";
    for(int i=0;i<[data length];i++){
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        if([newHexStr length]==1)
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        else
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
    }
    return hexStr;
}

+(NSString *)md5Encrypt:(NSString *)inPutText{
    const char *cStr = [inPutText UTF8String];
    unsigned char digest[16];
    CC_MD5( cStr,(CC_LONG)strlen(cStr), digest );
    
    NSData * base64 = [[NSData alloc]initWithBytes:digest length:16];
    //return [IPNGTMBase64 encodeBase64Data:base64];
    return [IPNDESUtil hexStringFromString:base64];
}

+(NSString *) sortString:(NSString *) inputText{
    NSArray* eles = [inputText componentsSeparatedByString:@"&"];
    NSMutableDictionary *dic=[NSMutableDictionary new];
    for (NSString* element in eles) {
        NSArray* keyValue = [element componentsSeparatedByString:@"="];
        if (keyValue.count==1 || [[keyValue lastObject] isEqualToString:@""]||[[[keyValue lastObject] lowercaseString] isEqualToString:@"null"])
            continue;
        
        [dic setValue:[keyValue lastObject] forKey:[keyValue firstObject]];
    }
    
    NSArray *keys = [dic allKeys];
    NSSortDescriptor *descriptor = [NSSortDescriptor sortDescriptorWithKey:nil ascending:YES];
    NSArray *descriptors = [NSArray arrayWithObject:descriptor];
    NSArray *sortedArray = [keys sortedArrayUsingDescriptors:descriptors];
    
    NSString *sortedString=@"";
    int time=0;
    for (NSString *key in sortedArray) {
        NSString *value=[dic objectForKey:key];
        if (key==nil)
            continue;

        if (time>0)
            sortedString=[NSString stringWithFormat:@"%@&%@=%@",sortedString, key,value];
        else
            sortedString=[NSString stringWithFormat:@"%@=%@", key,value];
        time++;
    }
    
    return [sortedString stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0"]];
}

@end
