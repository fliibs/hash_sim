#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "../include/ocm_id_remap.h"

typedef struct {
    const char* test_name;
    bool hash_2_bank_en;
    bool hash_3_bank_en;
    uint64_t base_addr_0;
    uint64_t addr_in;
    uint64_t xbar_hash_mask;
    uint64_t niu_hash_mask;
    bool xbar_hash_en;
    uint8_t hash_mode;
    uint32_t expected_result;
} test_case_t;

void print_test_result(const test_case_t* test, uint32_t result, bool passed) {
    printf("Test: %s\n", test->test_name);
    printf("  Input: hash_2_bank_en=%d, hash_3_bank_en=%d, base_addr_0=0x%lx, addr_in=0x%lx\n",
           test->hash_2_bank_en, test->hash_3_bank_en, test->base_addr_0, test->addr_in);
    printf("         xbar_hash_mask=0x%lx, niu_hash_mask=0x%lx, xbar_hash_en=%d, hash_mode=%d\n",
           test->xbar_hash_mask, test->niu_hash_mask, test->xbar_hash_en, test->hash_mode);
    printf("  Expected: 0x%x\n", test->expected_result);
    printf("  Actual:   0x%x\n", result);
    printf("  Status:   %s\n\n", passed ? "PASS" : "FAIL");
}

bool run_test_case(const test_case_t* test) {
    uint32_t result = ocm_id_remap(
        test->hash_2_bank_en,
        test->hash_3_bank_en,
        test->base_addr_0,
        test->addr_in,
        test->xbar_hash_mask,
        test->niu_hash_mask,
        test->xbar_hash_en,
        test->hash_mode
    );
    
    bool passed = (result == test->expected_result);
    if (passed == 0) print_test_result(test, result, passed);
    return passed;
}

int main() {
    printf("OCM ID Remap Test Suite\n");
    printf("=======================\n\n");
    
    test_case_t test_cases[] = {
        // 测试用例 1: 禁用哈希功能
        {
            "Hash disabled",
            false, false, M0, M1 + 0x1000, 
            GRAN_1K, GRAN_2K, false, 0,
            0x1000  // 直接返回有效地址
        },
        
        // 测试用例 2: 2bank模式，GRAN_1K
        {
            "2bank mode, GRAN_1K, base 0",
            true, false, M0, M0 + 0x1000, 
            GRAN_1K, GRAN_2K, true, 0,
            0x1000  // 没有bank选择位设置
        },
        
        // 测试用例 3: 2bank模式，GRAN_1K，base 1
        {
            "2bank mode, GRAN_1K, base 1",
            true, false, M0, M1 + 0x1000, 
            GRAN_1K, GRAN_2K, true, 0,
            0x1000 | (1 << 10)  // 设置bank选择位
        },

        // 测试用例 4: 3bank模式，GRAN_1K
        {
            "3bank mode, GRAN_1K, base 0",
            false, true, M0, M0 + 0x1000, 
            GRAN_1K, GRAN_2K, true, 1,
            0x800  // base 0，没有额外偏移
        },
        
        // 测试用例 5: 3bank模式，GRAN_1K，base 2
        {
            "3bank mode, GRAN_1K, base 5",
            false, true, M0, M5 + 0x1000, 
            GRAN_1K, GRAN_2K, true, 1,
            (5 << 19) | 0x800  // base 2，有偏移
        },
        
        // 测试用例 6: 不同粒度测试 - GRAN_256
        {
            "2bank mode, GRAN_256, base 1",
            true, false, M0, M2 + 0x100, 
            GRAN_256, GRAN_512, true, 0,
            (0x100 & ~(1<<8) & ~(1<<9)) | (2 << 8)  // 使用8位粒度
        },
        
        // 测试用例 7: 不同粒度测试 - GRAN_512
        {
            "2bank mode, GRAN_512, base 3",
            true, false, M0, M1 + 0x200, 
            GRAN_512, GRAN_1K, true, 0,
            0x200 | (1 << 9)  // 使用9位粒度
        },
        
        // 测试用例 8: 不同粒度测试 - GRAN_2K
        {
            "2bank mode, GRAN_2K, base 1",
            true, false, M0, M1 + 0x800, 
            GRAN_1K, GRAN_2K, true, 0,
            (0x800 & ~(1<<10) & ~(1<<11))| (1 << 10)  // 使用11位粒度
        },
        
        // 测试用例 9: 边界条件测试 - 基地址边界
        {
            "Boundary test - base address edge",
            true, false, M0, M4 - 1, 
            GRAN_1K, GRAN_2K, true, 0,
            (M1 - 1 - M0)  // 应该在base 0范围内
        },
        
        // 测试用例 10: 边界条件测试 - 模式不匹配
        {
            "Mode mismatch test",
            false, false, M0, M2 + 0x1000, 
            GRAN_1K, GRAN_2K, false, 0,
            0x1000  // 两种bank模式都禁用，应直接返回有效地址
        },

        // 测试用例 11: 3bank模式，GRAN_256,base 4
        {
            "3bank mode, GRAN_256, base 5",
            false, true, M0, M4 + 0x100, 
            GRAN_256, GRAN_512, true, 1,
            (4 << 19) | 0x000  // base 2，有偏移
        },

        // 测试用例 11: 3bank模式，GRAN_256,base 4
        {
            "3bank mode, GRAN_512, base 3",
            false, true, M0, M3 + 0x0200, 
            GRAN_512, GRAN_512, true, 1,
            (3 << 19) | 0x000  // base 2，有偏移
        }
    };
    
    int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    int passed_tests = 0;
    
    for (int i = 0; i < num_tests; i++) {
        if (run_test_case(&test_cases[i])) {
            passed_tests++;
        }
    }
    // run_test_case(&test_cases[3]);
    
    // 打印总结
    printf("Test Summary\n");
    printf("============\n");
    printf("Total tests: %d\n", num_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", num_tests - passed_tests);
    printf("Success rate: %.1f%%\n", (float)passed_tests / num_tests * 100);
    
    return (passed_tests == num_tests) ? 0 : 1;
}