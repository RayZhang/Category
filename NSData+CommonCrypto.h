//
//  NSData+CommonCrypto.h
//
//  Created by Ray Zhang on 13-3-1.
//  Copyright (c) 2013年 Ray Zhang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (CommonCrypto)

- (NSString *)MD5;
- (NSString *)SHAWithDigestLength:(NSUInteger)length;

- (id)DESEncryptWithKey:(NSString *)encryptKey;
- (id)DESDecryptWithKey:(NSString *)decryptKey;

- (id)AES256EncryptWithKey:(NSString *)encryptKey;
- (id)AES256DecryptWithKey:(NSString *)decryptKey;

@end
