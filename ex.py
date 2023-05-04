import re

password = str(input())
 ## 영문자 대소문자, 숫자, 언더바(_)만 허용


import re

pattern = re.compile(r'^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$')

if not pattern.match(password):
    print("유효성 검사 로직 불통")

#re.compile([^a-zA-Z0-9])