<?php

use app\common\logic\RunMap;
use app\common\model\HostModel;
use think\Db;

// 调试模式
define('LXDSERVER_DEBUG', true);

function lxdserver_debug($message, $data = null) {
    if (!LXDSERVER_DEBUG) return;

    $log = '[LXD-DEBUG] ' . $message;
    if ($data !== null) {
        $log .= ' | Data: ' . json_encode($data, JSON_UNESCAPED_UNICODE);
    }
    error_log($log);
}

// 插件元数据信息
function lxdserver_MetaData()
{
    return [
        'DisplayName' => '魔方财务-LXD对接插件 by xkatld',
        'APIVersion'  => '1.0.0',
        'HelpDoc'     => 'https://github.com/xkatld/zjmf-lxd-server',
    ];
}

// 定义产品配置选项
function lxdserver_ConfigOptions()
{
    return [
        'image' => [
            'type'        => 'text',
            'name'        => '镜像',
            'description' => '容器镜像名称, 如: debian/12',
            'default'     => 'debian/12',
            'key'         => 'image',
        ],
        'cpus' => [
            'type'        => 'text',
            'name'        => 'CPU核心数',
            'description' => '容器的CPU核心数量',
            'default'     => '1',
            'key'         => 'cpus',
        ],
        'memory' => [
            'type'        => 'text',
            'name'        => '内存',
            'description' => '容器的内存大小, 支持MB/GB/TB',
            'default'     => '256MB',
            'key'         => 'memory',
        ],
        'disk' => [
            'type'        => 'text',
            'name'        => '硬盘',
            'description' => '容器的硬盘大小, 支持MB/GB/TB',
            'default'     => '512MB',
            'key'         => 'disk',
        ],
        'ingress' => [
            'type'        => 'text',
            'name'        => '入站带宽',
            'description' => '容器的入站带宽限制, 支持kbit/Mbit/Gbit',
            'default'     => '100Mbit',
            'key'         => 'ingress',
        ],
        'egress' => [
            'type'        => 'text',
            'name'        => '出站带宽',
            'description' => '容器的出站带宽限制, 支持kbit/Mbit/Gbit',
            'default'     => '100Mbit',
            'key'         => 'egress',
        ],
        'nat_limit' => [
            'type'        => 'text',
            'name'        => 'NAT规则数量',
            'description' => 'NAT端口转发规则的数量限制',
            'default'     => '5',
            'key'         => 'nat_limit',
        ],
        'traffic_limit' => [
            'type'        => 'text',
            'name'        => '月流量限制',
            'description' => '每月流量限制(GB), 0为不限制',
            'default'     => '100',
            'key'         => 'traffic_limit',
        ],
        'cpu_allowance' => [
            'type'        => 'text',
            'name'        => 'CPU使用率限制',
            'description' => 'CPU使用率百分比, 如: 50%',
            'default'     => '50%',
            'key'         => 'cpu_allowance',
        ],
        'cpu_priority' => [
            'type'        => 'dropdown',
            'name'        => 'CPU调度优先级',
            'description' => 'CPU调度优先级 (0-10)',
            'default'     => '5',
            'key'         => 'cpu_priority',
            'options'     => array_combine(range(0, 10), range(0, 10)),
        ],
        'memory_swap' => [
            'type'        => 'dropdown',
            'name'        => 'Swap开关',
            'description' => '是否允许使用Swap',
            'default'     => 'true',
            'key'         => 'memory_swap',
            'options'     => ['true' => '启用', 'false' => '禁用'],
        ],
        'memory_swap_priority' => [
            'type'        => 'dropdown',
            'name'        => 'Swap优先级',
            'description' => 'Swap优先级 (0-10)',
            'default'     => '5',
            'key'         => 'memory_swap_priority',
            'options'     => array_combine(range(0, 10), range(0, 10)),
        ],
        'disk_priority' => [
            'type'        => 'dropdown',
            'name'        => '磁盘IO优先级',
            'description' => '磁盘IO优先级 (0-10)',
            'default'     => '5',
            'key'         => 'disk_priority',
            'options'     => array_combine(range(0, 10), range(0, 10)),
        ],
        'disk_read_limit' => [
            'type'        => 'text',
            'name'        => '磁盘读取限速',
            'description' => '磁盘每秒读取速度限制, 如: 100MB',
            'default'     => '100MB',
            'key'         => 'disk_read_limit',
        ],
        'disk_write_limit' => [
            'type'        => 'text',
            'name'        => '磁盘写入限速',
            'description' => '磁盘每秒写入速度限制, 如: 100MB',
            'default'     => '100MB',
            'key'         => 'disk_write_limit',
        ],
        'max_processes' => [
            'type'        => 'text',
            'name'        => '最大进程数',
            'description' => '限制容器最大进程数',
            'default'     => '512',
            'key'         => 'max_processes',
        ],
        'max_nofile' => [
            'type'        => 'text',
            'name'        => '最大文件描述符数',
            'description' => '限制容器内最大文件/连接数',
            'default'     => '1048576',
            'key'         => 'max_nofile',
        ],
        'allow_nesting' => [
            'type'        => 'dropdown',
            'name'        => '嵌套虚拟化',
            'description' => '是否允许容器内运行虚拟化',
            'default'     => 'true',
            'key'         => 'allow_nesting',
            'options'     => ['true' => '启用', 'false' => '禁用'],
        ],
        'privileged' => [
            'type'        => 'dropdown',
            'name'        => '特权模式',
            'description' => '是否允许特权容器运行',
            'default'     => 'false',
            'key'         => 'privileged',
            'options'     => ['false' => '禁用 (推荐)', 'true' => '启用'],
        ],
        'udp_enabled' => [
            'type'        => 'dropdown',
            'name'        => 'UDP协议支持',
            'description' => '是否允许创建UDP端口转发规则',
            'default'     => 'false',
            'key'         => 'udp_enabled',
            'options'     => ['false' => '禁用 (推荐)', 'true' => '启用'],
        ],

    ];
}

// 测试与API服务器的连接
function lxdserver_TestLink($params)
{
    lxdserver_debug('开始测试API连接', $params);

    $data = [
        'url'  => '/api/check',
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];

    $res = lxdserver_Curl($params, $data, 'GET');
    lxdserver_debug('API连接测试响应', $res);

    if ($res === null) {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 0,
                'msg'           => "连接失败: 无法连接到服务器"
            ]
        ];
    } elseif (isset($res['error'])) {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 0,
                'msg'           => "连接失败: " . $res['error']
            ]
        ];
    } elseif (isset($res['code']) && $res['code'] == 200) {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 1,
                'msg'           => "连接成功"
            ]
        ];
    } elseif (isset($res['lxd_version'])) {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 1,
                'msg'           => "连接成功"
            ]
        ];
    } elseif (isset($res['code'])) {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 0,
                'msg'           => "连接失败: " . ($res['msg'] ?? '服务器返回错误')
            ]
        ];
    } else {
        return [
            'status' => 200,
            'data'   => [
                'server_status' => 0,
                'msg'           => "连接失败: 响应格式异常"
            ]
        ];
    }
}

// 定义客户区域的页面
function lxdserver_ClientArea($params)
{
    return [
        'info'    => ['name' => '产品信息'],
        'nat_acl' => ['name' => 'NAT转发'],
    ];
}

// 处理客户区域页面的内容和API请求
function lxdserver_ClientAreaOutput($params, $key)
{
    lxdserver_debug('ClientAreaOutput调用', ['key' => $key, 'action' => $_GET['action'] ?? null]);

    if (isset($_GET['action'])) {
        $action = $_GET['action'];
        lxdserver_debug('处理API请求', ['action' => $action, 'domain' => $params['domain'] ?? null]);

        if (empty($params['domain'])) {
            header('Content-Type: application/json');
            echo json_encode(['code' => 400, 'msg' => '容器域名未设置']);
            exit;
        }

        $apiEndpoints = [
            'getinfo'    => '/api/status',
            'getstats'   => '/api/info',
            'gettraffic' => '/api/traffic',
            'getinfoall' => '/api/info',
            'natlist'    => '/api/natlist',
        ];

        $apiEndpoint = $apiEndpoints[$action] ?? '';

        if (!$apiEndpoint) {
            header('Content-Type: application/json');
            echo json_encode(['code' => 400, 'msg' => '不支持的操作: ' . $action]);
            exit;
        }

        $requestData = [
            'url'  => $apiEndpoint . '?hostname=' . $params['domain'],
            'type' => 'application/x-www-form-urlencoded',
            'data' => [],
        ];

        lxdserver_debug('发送API请求', $requestData);
        $res = lxdserver_Curl($params, $requestData, 'GET');
        lxdserver_debug('API响应', $res);

        if ($res === null) {
            $res = ['code' => 500, 'msg' => '连接服务器失败'];
        } elseif (!is_array($res)) {
            $res = ['code' => 500, 'msg' => '服务器返回了无效的响应格式'];
        } else {
            $res = lxdserver_TransformAPIResponse($action, $res);
        }

        header('Content-Type: application/json');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        echo json_encode($res);
        exit;
    }

    if ($key == 'info') {
        return [
            'template' => 'templates/info.html',
            'vars'     => [],
        ];
    }

    if ($key == 'nat_acl') {
        $requestData = [
            'url'  => '/api/natlist?hostname=' . $params['domain'] . '&_t=' . time(),
            'type' => 'application/x-www-form-urlencoded',
            'data' => [],
        ];
        $res = lxdserver_Curl($params, $requestData, 'GET');

        $nat_limit = intval($params['configoptions']['nat_limit'] ?? 5);
        $current_count = lxdserver_getNATRuleCount($params);
        $udp_enabled = ($params['configoptions']['udp_enabled'] ?? 'false') === 'true';

        return [
            'template' => 'templates/nat.html',
            'vars'     => [
                'list' => $res['data'] ?? [],
                'msg'  => $res['msg'] ?? '',
                'nat_limit' => $nat_limit,
                'current_count' => $current_count,
                'remaining_count' => max(0, $nat_limit - $current_count),
                'udp_enabled' => $udp_enabled,
            ],
        ];
    }
}

// 定义允许客户端调用的函数
function lxdserver_AllowFunction()
{
    return [
        'client' => ['natadd', 'natdel', 'natlist'],
    ];
}

// 创建LXD容器 (开通产品)
function lxdserver_CreateAccount($params)
{
    lxdserver_debug('开始创建容器', ['domain' => $params['domain']]);

    $sys_pwd = $params['password'] ?? randStr(8);

    $data = [
        'url'  => '/api/create',
        'type' => 'application/json',
        'data' => [
            'hostname'      => $params['domain'],
            'password'      => $sys_pwd,
            'cpus'          => (int)($params['configoptions']['cpus'] ?? 1),
            'memory'        => $params['configoptions']['memory'] ?? '512MB',
            'disk'          => $params['configoptions']['disk'] ?? '10GB',
            'disk_priority' => (int)($params['configoptions']['disk_priority'] ?? 5),
            'image'         => $params['configoptions']['image'] ?? 'ubuntu24',
            'ingress'       => $params['configoptions']['ingress'] ?? '100Mbit',
            'egress'        => $params['configoptions']['egress'] ?? '100Mbit',
            'allow_nesting' => ($params['configoptions']['allow_nesting'] ?? 'false') === 'true',
            'traffic_limit' => (int)($params['configoptions']['traffic_limit'] ?? 0),

            // 高级配置
            'cpu_allowance'  => $params['configoptions']['cpu_allowance'] ?? '100%',
            'cpu_priority'   => (int)($params['configoptions']['cpu_priority'] ?? 5),
            'memory_swap'           => ($params['configoptions']['memory_swap'] ?? 'true') === 'true',
            'memory_swap_priority'  => (int)($params['configoptions']['memory_swap_priority'] ?? 1),
            'max_processes'  => (int)($params['configoptions']['max_processes'] ?? 512),
            'max_nofile'     => (int)($params['configoptions']['max_nofile'] ?? 1048576),
            'disk_read_limit'   => $params['configoptions']['disk_read_limit'] ?? '',
            'disk_write_limit'  => $params['configoptions']['disk_write_limit'] ?? '',
            'privileged'     => ($params['configoptions']['privileged'] ?? 'false') === 'true',
        ],
    ];

    lxdserver_debug('发送创建请求', $data);
    $res = lxdserver_JSONCurl($params, $data, 'POST');
    lxdserver_debug('创建响应', $res);

    if (isset($res['code']) && $res['code'] == '200') {
        $dedicatedip_value = $params['server_ip'];

        if (!empty($res['data']['ssh_port'])) {
            $ssh_port = $res['data']['ssh_port'];
            $dedicatedip_value = $params['server_ip'] . ':' . $ssh_port;
            lxdserver_debug('获取到SSH端口', ['ssh_port' => $ssh_port]);
        } else {
            lxdserver_debug('警告：响应中没有SSH端口信息', $res);
        }

        $update = [
            'dedicatedip'  => $dedicatedip_value,
            'domainstatus' => 'Active',
            'username'     => 'root',
        ];

        // 如果API返回了SSH端口，则更新port字段
        if (!empty($res['data']['ssh_port'])) {
            $update['port'] = $res['data']['ssh_port'];
        }

        try {
            Db::name('host')->where('id', $params['hostid'])->update($update);
            lxdserver_debug('数据库更新成功', $update);
        } catch (\Exception $e) {
             return ['status' => 'error', 'msg' => ($res['msg'] ?? '创建成功，但同步数据到面板失败: ' . $e->getMessage())];
        }

        return ['status' => 'success', 'msg' => $res['msg'] ?? '创建成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '创建失败'];
    }
}

// 同步容器信息
function lxdserver_Sync($params)
{
    $data = [
        'url'  => '/api/status?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    if (isset($res['code']) && $res['code'] == '200') {
        if (class_exists('think\Db') && isset($params['hostid'])) {
            try {
                $dedicatedip_value = $params['server_ip'];

                if (isset($res['data']['ssh_port']) && !empty($res['data']['ssh_port'])) {
                    $dedicatedip_value = $params['server_ip'] . ':' . $res['data']['ssh_port'];
                }

                Db::name('host')->where('id', $params['hostid'])->update([
                    'dedicatedip' => $dedicatedip_value,
                ]);
            } catch (Exception $e) {
                lxdserver_debug('同步数据库失败', ['error' => $e->getMessage()]);
            }
        }
        return ['status' => 'success', 'msg' => $res['msg'] ?? '同步成功'];
    }

    return ['status' => 'error', 'msg' => $res['msg'] ?? '同步失败'];
}

// 删除LXD容器 (删除产品)
function lxdserver_TerminateAccount($params)
{
    $data = [
        'url'  => '/api/delete?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    return isset($res['code']) && $res['code'] == '200'
        ? ['status' => 'success', 'msg' => $res['msg'] ?? '删除成功']
        : ['status' => 'error', 'msg' => $res['msg'] ?? '删除失败'];
}

// 启动LXD容器
function lxdserver_On($params)
{
    $data = [
        'url'  => '/api/boot?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    return isset($res['code']) && $res['code'] == '200'
        ? ['status' => 'success', 'msg' => $res['msg'] ?? '开机成功']
        : ['status' => 'error', 'msg' => $res['msg'] ?? '开机失败'];
}

// 关闭LXD容器
function lxdserver_Off($params)
{
    $data = [
        'url'  => '/api/stop?' . 'hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    if (isset($res['code']) && $res['code'] == '200') {
        return ['status' => 'success', 'msg' => $res['msg'] ?? '关机成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '关机失败'];
    }
}

// 暂停LXD容器 (产品暂停)
function lxdserver_SuspendAccount($params)
{
    lxdserver_debug('开始暂停容器', ['domain' => $params['domain']]);

    $data = [
        'url'  => '/api/suspend?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    lxdserver_debug('暂停容器响应', $res);

    if (isset($res['code']) && $res['code'] == '200') {
        return ['status' => 'success', 'msg' => $res['msg'] ?? '容器暂停任务已提交'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '容器暂停失败'];
    }
}

// 恢复LXD容器 (解除暂停)
function lxdserver_UnsuspendAccount($params)
{
    lxdserver_debug('开始解除暂停容器', ['domain' => $params['domain']]);

    $data = [
        'url'  => '/api/unsuspend?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    lxdserver_debug('解除暂停容器响应', $res);

    if (isset($res['code']) && $res['code'] == '200') {
        return ['status' => 'success', 'msg' => $res['msg'] ?? '容器恢复任务已提交'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '容器恢复失败'];
    }
}

// 重启LXD容器
function lxdserver_Reboot($params)
{
    $data = [
        'url'  => '/api/reboot?' . 'hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    if (isset($res['code']) && $res['code'] == '200') {
        return ['status' => 'success', 'msg' => $res['msg'] ?? '重启成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '重启失败'];
    }
}

// 获取容器NAT规则数量
function lxdserver_getNATRuleCount($params)
{
    $data = [
        'url'  => '/api/natlist?hostname=' . urlencode($params['domain']),
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];

    $res = lxdserver_Curl($params, $data, 'GET');

    if (isset($res['code']) && $res['code'] == 200 && isset($res['data']) && is_array($res['data'])) {
        return count($res['data']);
    }

    return 0;
}

// 添加NAT端口转发
function lxdserver_natadd($params)
{
    parse_str(file_get_contents("php://input"), $post);

    $dport = intval($post['dport'] ?? 0);
    $sport = intval($post['sport'] ?? 0);
    $dtype = strtolower(trim($post['dtype'] ?? ''));
    $udp_enabled = ($params['configoptions']['udp_enabled'] ?? 'false') === 'true';

    // 验证协议类型
    if (!in_array($dtype, ['tcp', 'udp'])) {
        return ['status' => 'error', 'msg' => '不支持的协议类型，仅支持TCP和UDP'];
    }
    
    // 检查UDP是否启用
    if ($dtype === 'udp' && !$udp_enabled) {
        return ['status' => 'error', 'msg' => 'UDP协议未启用，请联系管理员开启UDP支持'];
    }
    if ($sport <= 0 || $sport > 65535) {
        return ['status' => 'error', 'msg' => '容器内部端口超过范围'];
    }

    // 检查NAT规则数量限制
    $nat_limit = intval($params['configoptions']['nat_limit'] ?? 5);

    $current_count = lxdserver_getNATRuleCount($params);
    if ($current_count >= $nat_limit) {
        return ['status' => 'error', 'msg' => "NAT规则数量已达到限制（{$nat_limit}条），无法添加更多规则"];
    }

    // 由后端自动分配外网端口，不接受前端传入的dport
    $requestData = 'hostname=' . urlencode($params['domain']) . '&dtype=' . urlencode($dtype) . '&sport=' . $sport;

    $data = [
        'url'  => '/api/addport',
        'type' => 'application/x-www-form-urlencoded',
        'data' => $requestData,
    ];

    $res = lxdserver_Curl($params, $data, 'POST');

    if (isset($res['code']) && $res['code'] == 200) {
        return ['status' => 'success', 'msg' => $res['msg'] ?? 'NAT转发添加成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? 'NAT转发添加失败'];
    }
}

// 删除NAT端口转发
function lxdserver_natdel($params)
{
    parse_str(file_get_contents("php://input"), $post);

    $dport = intval($post['dport'] ?? 0);
    $sport = intval($post['sport'] ?? 0);
    $dtype = strtolower(trim($post['dtype'] ?? ''));
    $udp_enabled = ($params['configoptions']['udp_enabled'] ?? 'false') === 'true';

    // 验证协议类型
    if (!in_array($dtype, ['tcp', 'udp'])) {
        return ['status' => 'error', 'msg' => '不支持的协议类型，仅支持TCP和UDP'];
    }
    
    // 检查UDP是否启用（只针对新创建，删除时允许删除已存在的UDP规则）
    if ($dtype === 'udp' && !$udp_enabled) {
        // 删除操作允许删除已存在的UDP规则，但不允许创建新的
        // return ['status' => 'error', 'msg' => 'UDP协议未启用'];
    }
    if ($sport <= 0 || $sport > 65535) {
        return ['status' => 'error', 'msg' => '容器内部端口超过范围'];
    }
    if ($dport < 10000 || $dport > 65535) {
        return ['status' => 'error', 'msg' => '外网端口映射范围为10000-65535'];
    }

    $data = [
        'url'  => '/api/delport',
        'type' => 'application/x-www-form-urlencoded',
        'data' => 'hostname=' . urlencode($params['domain']) . '&dtype=' . urlencode($dtype) . '&dport=' . $dport . '&sport=' . $sport,
    ];

    $res = lxdserver_Curl($params, $data, 'POST');

    if (isset($res['code']) && $res['code'] == 200) {
        return ['status' => 'success', 'msg' => $res['msg'] ?? 'NAT转发删除成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? 'NAT转发删除失败'];
    }
}

// 查询容器运行状态
function lxdserver_Status($params)
{
    $data = [
        'url'  => '/api/status?' . 'hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    if (isset($res['code']) && $res['code'] == 200) {
        $result = ['status' => 'success'];

        $containerStatus = $res['data']['status'] ?? '';

        // 将LXD状态映射为ZJMF状态
        switch (strtoupper($containerStatus)) {
            case 'RUNNING':
                $result['data']['status'] = 'on';
                $result['data']['des'] = '开机';
                break;
            case 'STOPPED':
                $result['data']['status'] = 'off';
                $result['data']['des'] = '关机';
                break;
            case 'FROZEN':
                $result['data']['status'] = 'suspend';
                $result['data']['des'] = '流量超标-暂停';
                break;
            default:
                $result['data']['status'] = 'unknown';
                $result['data']['des'] = '未知状态';
                break;
        }

        return $result;
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '获取状态失败'];
    }
}

// 重置容器密码
function lxdserver_CrackPassword($params, $new_pass)
{
    $data = [
        'url'  => '/api/password',
        'type' => 'application/json',
        'data' => [
            'hostname' => $params['domain'],
            'password' => $new_pass,
        ],
    ];
    $res = lxdserver_JSONCurl($params, $data, 'POST');

    if (isset($res['code']) && $res['code'] == 200) {
        try {
            Db::name('host')->where('id', $params['hostid'])->update(['password' => $new_pass]);
        } catch (\Exception $e) {
            return ['status' => 'error', 'msg' => ($res['msg'] ?? $res['message'] ?? 'LXD容器密码重置成功，但同步新密码到面板数据库失败: ' . $e->getMessage())];
        }
        return ['status' => 'success', 'msg' => $res['msg'] ?? $res['message'] ?? '密码重置成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? $res['message'] ?? '密码重置失败'];
    }
}

// 重装容器操作系统
function lxdserver_Reinstall($params)
{
    if (empty($params['reinstall_os'])) {
        return ['status' => 'error', 'msg' => '操作系统参数错误'];
    }

    $reinstall_pass = $params['password'] ?? randStr(8);

    $data = [
        'url'  => '/api/reinstall',
        'type' => 'application/json',
        'data' => [
            'hostname' => $params['domain'],
            'system'   => $params['reinstall_os'],
            'password' => $reinstall_pass,

            'cpus'          => (int)($params['configoptions']['cpus'] ?? 1),
            'memory'        => $params['configoptions']['memory'] ?? '512MB',
            'disk'          => $params['configoptions']['disk'] ?? '10GB',
            'disk_priority' => (int)($params['configoptions']['disk_priority'] ?? 5),
            'ingress'       => $params['configoptions']['ingress'] ?? '100Mbit',
            'egress'        => $params['configoptions']['egress'] ?? '100Mbit',
            'allow_nesting' => ($params['configoptions']['allow_nesting'] ?? 'false') === 'true',
            'traffic_limit' => (int)($params['configoptions']['traffic_limit'] ?? 0),
            'cpu_allowance'  => $params['configoptions']['cpu_allowance'] ?? '100%',
            'cpu_priority'   => (int)($params['configoptions']['cpu_priority'] ?? 5),
            'memory_swap'           => ($params['configoptions']['memory_swap'] ?? 'true') === 'true',
            'memory_swap_priority'  => (int)($params['configoptions']['memory_swap_priority'] ?? 1),
            'max_processes'  => (int)($params['configoptions']['max_processes'] ?? 512),
            'max_nofile'     => (int)($params['configoptions']['max_nofile'] ?? 1048576),
            'disk_read_limit'   => $params['configoptions']['disk_read_limit'] ?? '',
            'disk_write_limit'  => $params['configoptions']['disk_write_limit'] ?? '',
            'privileged'     => ($params['configoptions']['privileged'] ?? 'false') === 'true',
        ],
    ];
    $res = lxdserver_JSONCurl($params, $data, 'POST');

    if (isset($res['code']) && $res['code'] == 200) {
        return ['status' => 'success', 'msg' => $res['msg'] ?? $res['message'] ?? '重装成功'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? $res['message'] ?? '重装失败'];
    }
}

// 发送JSON格式的cURL请求
function lxdserver_JSONCurl($params, $data = [], $request = 'POST')
{
    $curl = curl_init();

    // API服务器强制启用HTTPS
    $protocol = 'https';
    $url = $protocol . '://' . $params['server_ip'] . ':' . $params['port'] . $data['url'];

    $curlOptions = [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING       => '',
        CURLOPT_MAXREDIRS      => 10,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST  => $request,
        CURLOPT_POSTFIELDS     => json_encode($data['data']),
        CURLOPT_HTTPHEADER     => [
            'apikey: ' . $params['accesshash'],
            'Content-Type: application/json',
        ],
    ];

    // 支持自签证书
    $curlOptions[CURLOPT_SSL_VERIFYPEER] = false;
    $curlOptions[CURLOPT_SSL_VERIFYHOST] = false;
    $curlOptions[CURLOPT_SSLVERSION] = CURL_SSLVERSION_TLSv1_2;

    curl_setopt_array($curl, $curlOptions);

    $response = curl_exec($curl);
    $errno    = curl_errno($curl);

    curl_close($curl);

    if ($errno) {
        return null;
    }

    return json_decode($response, true);
}

// 发送通用的cURL请求
function lxdserver_Curl($params, $data = [], $request = 'POST')
{
    $curl = curl_init();

    // API服务器强制启用HTTPS
    $protocol = 'https';
    $url = $protocol . '://' . $params['server_ip'] . ':' . $params['port'] . $data['url'];

    lxdserver_debug('发送请求', [
        'url' => $url,
        'method' => $request,
        'secure' => $isSecure
    ]);

    $postFields = ($request === 'POST' || $request === 'PUT') ? ($data['data'] ?? null) : null;
    if ($request === 'GET' && !empty($data['data']) && is_array($data['data'])) {
        $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($data['data']);
    } elseif ($request === 'GET' && !empty($data['data']) && is_string($data['data'])) {
         $url .= (strpos($url, '?') === false ? '?' : '&') . $data['data'];
    }

    $curlOptions = [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING       => '',
        CURLOPT_MAXREDIRS      => 10,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST  => $request,
        CURLOPT_HTTPHEADER     => [
            'apikey: ' . $params['accesshash'],
            'Content-Type: ' . ($data['type'] ?? 'application/x-www-form-urlencoded'),
        ],
    ];

    // 支持自签证书
    $curlOptions[CURLOPT_SSL_VERIFYPEER] = false;
    $curlOptions[CURLOPT_SSL_VERIFYHOST] = false;
    $curlOptions[CURLOPT_SSLVERSION] = CURL_SSLVERSION_TLSv1_2;

    curl_setopt_array($curl, $curlOptions);

    if ($postFields !== null) {
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postFields);
    }

    $response = curl_exec($curl);
    $errno    = curl_errno($curl);
    $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $curlError = curl_error($curl);

    curl_close($curl);

    lxdserver_debug('请求响应', [
        'http_code' => $httpCode,
        'response_length' => strlen($response),
        'curl_errno' => $errno,
        'curl_error' => $curlError
    ]);

    if ($errno) {
        lxdserver_debug('CURL错误', [
            'errno' => $errno,
            'error' => $curlError,
            'error_desc' => curl_strerror($errno)
        ]);
        return null;
    }

    $decoded = json_decode($response, true);
    lxdserver_debug('解析响应', ['code' => $decoded['code'] ?? 'NO CODE']);
    return $decoded;
}

// 转换API响应以适配前端
function lxdserver_TransformAPIResponse($action, $response)
{
    // 优先处理Go API的错误响应
    if (isset($response['error'])) {
        return [
            'code' => 400,
            'msg' => $response['error']
        ];
    }

    if (!isset($response['code']) || $response['code'] != 200) {
        return $response; 
    }

    switch ($action) {
        case 'getinfo':
            return $response;

        case 'getstats':
        case 'getinfoall':
            if (isset($response['data'])) {
                $data = $response['data'];

                $transformed = [
                    'code' => 200,
                    'msg' => '获取容器信息成功',
                    'data' => [
                        'hostname' => $data['hostname'] ?? '',
                        'status' => $data['status'] ?? '',
                        'ipv4' => $data['ipv4'] ?? '',
                        'ipv6' => $data['ipv6'] ?? '',
                        'type' => $data['type'] ?? '',
                        'created_at' => $data['created_at'] ?? '',
                        'cpus' => $data['config']['cpus'] ?? 1,
                        'memory' => $data['memory'] ?? 1024,
                        'disk' => $data['disk'] ?? 10240,
                        'config' => [
                            'cpus' => $data['config']['cpus'] ?? 1,
                            'memory' => $data['config']['memory'] ?? '1024 MB',
                            'disk' => $data['config']['disk'] ?? '10240 MB',
                            'traffic_limit' => $data['config']['traffic_limit'] ?? 0,
                        ],
                        'cpu_usage' => $data['usage']['cpu_usage'] ?? 0,
                        'memory_usage' => $data['usage']['memory_usage'] ?? '0 B',
                        'memory_usage_raw' => $data['usage']['memory_usage_raw'] ?? 0,
                        'disk_usage' => $data['usage']['disk_usage'] ?? '0 B',
                        'disk_usage_raw' => $data['usage']['disk_usage_raw'] ?? 0,
                        'traffic_usage' => $data['usage']['traffic_usage'] ?? '0 B',
                        'traffic_usage_raw' => $data['usage']['traffic_usage_raw'] ?? 0,
                        'cpu_percent' => $data['usage_percent']['cpu_percent'] ?? 0,
                        'memory_percent' => $data['usage_percent']['memory_percent'] ?? 0,
                        'disk_percent' => $data['usage_percent']['disk_percent'] ?? 0,
                        'last_update' => date('Y-m-d H:i:s'),
                        'timestamp' => time(),
                    ]
                ];

                return $transformed;
            }
            break;

        case 'gettraffic':
            if (isset($response['data']['used'])) {
                return [
                    'code' => 200,
                    'msg' => '获取流量使用量成功',
                    'data' => [
                        'used' => $response['data']['used'],
                    ]
                ];
            }
            break;
    }

    return $response;
}

// 获取NAT规则列表
function lxdserver_natlist($params)
{
    $requestData = [
        'url'  => '/api/natlist?' . 'hostname=' . $params['domain'] . '&_t=' . time(),
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $requestData, 'GET');
    if ($res === null) {
        return ['code' => 500, 'msg' => '连接API服务器失败', 'data' => []];
    }
    return $res;
}

// 获取Web控制台URL
function lxdserver_vnc($params) {
    lxdserver_debug('VNC控制台请求', ['domain' => $params['domain']]);

    $data = [
        'url'  => '/api/status?hostname=' . $params['domain'],
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];
    $res = lxdserver_Curl($params, $data, 'GET');

    if (!isset($res['code']) || $res['code'] != '200') {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '无法获取容器状态'];
    }

    if (!isset($res['data']['status']) || $res['data']['status'] !== 'RUNNING') {
        return ['status' => 'error', 'msg' => '容器未运行，无法连接控制台'];
    }

    $tokenData = [
        'url'  => '/api/console/create-token',
        'type' => 'application/json',
        'data' => [
            'hostname' => $params['domain'],
            'user_id' => (int)($params['userid'] ?? 0),
            'service_id' => (int)($params['serviceid'] ?? 0),
            'server_ip' => $params['server_ip'] ?? '',
            'expires_in' => 3600
        ],
    ];

    $tokenRes = lxdserver_JSONCurl($params, $tokenData, 'POST');
    lxdserver_debug('VNC令牌响应', $tokenRes);

    if (!isset($tokenRes['code']) || $tokenRes['code'] != 200) {
        return ['status' => 'error', 'msg' => $tokenRes['msg'] ?? '生成控制台令牌失败'];
    }

    $protocol = 'https';
    $consoleUrl = $protocol . '://' . $params['server_ip'] . ':' . $params['port'] . '/console?token=' . $tokenRes['data']['token'];

    lxdserver_debug('VNC控制台URL生成', ['url' => $consoleUrl]);

    return [
        'status' => 'success',
        'url' => $consoleUrl,
        'msg' => '控制台连接已准备就绪'
    ];
}

// 定义后台自定义按钮
function lxdserver_AdminButton($params)
{
    if (!empty($params['domain'])) {
        return [
            'TrafficReset' => '流量重置',
        ];
    }
    return [];
}

// 处理流量重置请求
function lxdserver_TrafficReset($params)
{
    lxdserver_debug('流量重置请求', ['domain' => $params['domain']]);

    if (empty($params['domain'])) {
        return ['status' => 'error', 'msg' => '容器域名参数缺失'];
    }

    $data = [
        'url'  => '/api/traffic/reset?hostname=' . urlencode($params['domain']),
        'type' => 'application/x-www-form-urlencoded',
        'data' => [],
    ];

    $res = lxdserver_Curl($params, $data, 'POST');
    lxdserver_debug('流量重置API响应', $res);

    if (isset($res['code']) && $res['code'] == 200) {
        return ['status' => 'success', 'msg' => $res['msg'] ?? '流量统计已重置'];
    } else {
        return ['status' => 'error', 'msg' => $res['msg'] ?? '流量重置失败'];
    }
}