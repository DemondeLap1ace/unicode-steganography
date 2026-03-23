本地复现的GlassWorm&Tycoon2FA用的编码部分，详情参见[http://test](http://test)

### 项目结构

├── README.md
├── LICENSE
├── .gitignore
├── run.bat                          #Windows 
├── run.sh                           #macOS 
├── pua-npm/                         #PUA + npm 
│   ├── build.py                    
│   ├── detect.py                    
│   ├── invisible-utils/            
│   │   ├── package.json
│   │   ├── README.md
│   │   └── lib/
│   │       ├── index.js             
│   │       └── setup.js             
│   └── consumer/                    
│       ├── package.json
│       └── app.js
├── hangul-browser/                  # 韩文字符+浏览器
│   ├── build.py                     
│   └── hangul_proxy_test.html       
└── .github/workflows/
    └── unicode-scan.yml       


### 其他命令

#### 自定义payload
python pua-npm/build.py --payload "console.log('custom')"

#### 从文件读取payload
python pua-npm/build.py --payload-file my_payload.js

#### 解码已有payload
python pua-npm/build.py --decode invisible-utils/lib/setup.js

#### 输出JSON
python pua-npm/detect.py . --json --exit-code

#### 显示命中位置的十六进制上下文
python pua-npm/detect.py invisible-utils/ --hex-context 16

#### 生成YARA检测规则
python pua-npm/detect.py invisible-utils/ --yara