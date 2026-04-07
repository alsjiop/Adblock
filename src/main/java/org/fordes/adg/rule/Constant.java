package org.fordes.adg.rule;

import java.io.File;

public class Constant {

    public static final String ROOT_PATH = System.getProperty("user.dir");

    public static final String UPDATE = "# Update time: {}\r\n";

    public static final String REPO = "# Repo URL: AdGuard、AdGuardHome广告过滤规则合并/去重\r\n\r\n###################################   合并/去重自以下规则   ####################################\r\n#- 'https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/easylist.txt' #xndeye-adblock_list\r\n#- 'https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/main/rule/all.txt'           #hululu1068/AdGuard-Rule\r\n#- 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt'          #hagezi/dns-blocklists-pro\r\n#- 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt'     #hagezi/dns-blocklists-pro-plus\r\n#- 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt'     #hagezi/dns-blocklists-ultimate\r\n#- 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt'          #Threat Intelligence Feeds\r\n#- 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt'   #Threat Intelligence Feeds-medium\r\n#- 'https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/full/hosts.txt'                 #neohosts\r\n#- 'https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/skyrules.txt'      #BlueSkyXN-skyrules\r\n# 本地规则\r\n# - 'mylist.txt'\r\n###############################################################################################\r\n\r\n# 每12小时同步一次、如有误杀、请手动解除\r\n\r\n";
    
    public static final String LOCAL_RULE_SUFFIX = ROOT_PATH + File.separator + "rule";

    /**
     * 基本的有效性检测正则，!开头，[]包裹，非特殊标记的#号开头均视为无效规则
     */
    public static final String EFFICIENT_REGEX = "^!|^#[^#,^@,^%,^\\$]|^\\[.*\\]$";

    /**
     * 去除首尾基础修饰符号 的正则，方便对规则进行分类
     * 包含：@@、||、@@||、/ 开头，$important、/ 结尾
     */
    public static final String BASIC_MODIFY_REGEX = "^@@\\|\\||^\\|\\||^@@|\\$important$|\\s#[^#]*$";

}
