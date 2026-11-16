#!/usr/bin/env python3
"""train/t2_constructs.py — bộ biểu thức "có cấu trúc tấn công rõ" dùng để lọc chất lượng dữ liệu huấn luyện tầng 2.

Từ 16/11/2026 bộ biểu thức nằm ở services/constructs.py, vì classifier cũng dùng nó (TIER2_CONSTRUCT_GATE). Tệp này chỉ nhập lại
để các công cụ dựng dữ liệu (t2_pool.py, t2_pool_result.py) và classifier luôn dùng CÙNG một bộ.

Vì sao cần khi dựng dữ liệu: một payload "lọt Cổng 2" trong dataset công khai có thể chỉ là payload hỏng hoặc một giá trị bình
thường nằm trong request bị gắn nhãn tấn công (đọc tay 15/11: chỉ 57/126 payload lọt là tấn công thật). Chỉ payload lọt Cổng 2 VÀ
có cấu trúc tấn công rõ mới được đánh dấu g2 = "pass"; payload lọt còn lại mang g2 = "pass_weak".
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "services"))
from constructs import RULES, any_construct, constructs      # noqa: E402,F401
