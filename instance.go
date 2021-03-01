package find_mysql

//用来查找当前操作系统上有多少正在运行到实例

import (
	"context"
	"fmt"
	"github.com/go-ini/ini"
	"github.com/shirou/gopsutil/process"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MySQLInstance struct {
	Pid          int     `json:"pid"`
	Name         string  `json:"name"`
	FullName     string  `json:"full_name"`
	User         string  `json:"user"`
	CmdLine      string  `json:"cmdline"`
	Ppid         int     `json:"parent_pid"`
	Pname        string  `json:"parent_name"`
	Puser        string  `json:"parent_user"`
	PcmdLine     string  `json:"parent_cmdline"`
	Port         int     `json:"port"`
	SocketFile   string  `json:"socket"`
	MycnfFile    string  `json:"mycnf"`
	BaseDir      string  `json:"basedir"`
	DataDir      string  `json:"datadir"`
	BinlogDir    string  `json:"binlogdir"`
	ErrorLogFile string  `json:"errorlog"`
	SlowLogFile  string  `json:"slowlog"`
	Verson       string  `json:"version"`
	VersonInfo   string  `json:"version_info"`
	Err          []error `json:"-"`
}

type MySQLInstanceList []MySQLInstance

func GetInstances() MySQLInstanceList {
	mysqlInstanceList := MySQLInstanceList{}
	ps, err := process.Processes()
	if err != nil {
		//fmt.Fprint(os.Stderr, err.Error())
		return mysqlInstanceList
	}
	for _, p := range ps {
		cmdSlice, err := p.CmdlineSlice()
		if err != nil {
			continue
		} else if len(cmdSlice) < 2 {
			continue
		}
		if strings.HasSuffix(cmdSlice[0], "mysqld") {
			//说明当前进程是MySQLd进程
			tmpInstance := new(MySQLInstance)
			if pParentId, err := p.Ppid(); err != nil {
				tmpInstance.Err = append(tmpInstance.Err, err)
			} else {
				if ok, err := process.PidExists(pParentId); err == nil && ok {
					//存在父进程
					if parentProc, err := process.NewProcess(pParentId); err == nil {
						tmpInstance.Ppid = int(parentProc.Pid)
						tmpInstance.Pname, _ = parentProc.Name()
						tmpInstance.Puser, _ = parentProc.Username()
						tmpInstance.PcmdLine, _ = parentProc.Cmdline()
					}
				} else if err != nil {
					tmpInstance.Err = append(tmpInstance.Err, err)
				}
			}
			tmpInstance.Pid = int(p.Pid)
			tmpInstance.Name, _ = p.Name()
			tmpInstance.FullName = cmdSlice[0]
			tmpInstance.User, _ = p.Username()
			tmpInstance.CmdLine, _ = p.Cmdline()

			//解析命令行参数找到my.cnf文件
			//开始解析cmdArgs
			argsMap := make(map[string]string, 0)
			for _, eachArg := range cmdSlice[1:] {
				//arg组成形式：--xx=df，-sads=df，--ss，-x形式，如果未带=说明是bool类型
				fields := strings.SplitN(eachArg, "=", 2)
				if len(fields) == 0 {
					continue
				} else if len(fields) == 1 {
					//处理bool类型
					argsMap[strings.TrimLeft(fields[0], "-")] = ""
				} else {
					//处理等值类型
					argsMap[strings.TrimLeft(fields[0], "-")] = fields[1]
				}
			}
			//从argsMap中查找是否存在对应的参数信息
			//先查看是否在参数中存在my.cnf你文件
			if v, ok := argsMap["defaults-file"]; ok {
				tmpInstance.MycnfFile = v
			} else {
				//查找路径/etc/my.cnf /etc/mysql/my.cnf /usr/local/mysql/etc/my.cnf ~/.my.cnf
				searchPathList := []string{
					"/etc/my.cnf",
					"/etc/mysql/my.cnf",
					"/usr/local/mysql/etc/my.cnf",
				}
				if userStruct, err := user.Lookup(tmpInstance.User); err == nil {
					searchPathList = append(searchPathList, filepath.Join(userStruct.HomeDir, ".my.cnf"))
				}
				for _, eachPath := range searchPathList {
					if _, err := os.Lstat(eachPath); err == nil {
						tmpInstance.MycnfFile = eachPath
						break
					}
				}
			}
			//开始查找basedir
			if v, ok := argsMap["basedir"]; ok {
				tmpInstance.BaseDir = v
			} else {
				tmpInstance.BaseDir = ReadCfgFromFile(tmpInstance.MycnfFile, "basedir")
			}
			//datadir
			if v, ok := argsMap["datadir"]; ok {
				tmpInstance.DataDir = v
			} else {
				tmpInstance.DataDir = ReadCfgFromFile(tmpInstance.MycnfFile, "datadir")
			}
			//log_bin
			if v, ok := argsMap["log-bin"]; ok {
				tmpInstance.BinlogDir = filepath.Dir(v)
			} else if v, ok := argsMap["log_bin"]; ok {
				tmpInstance.BinlogDir = filepath.Dir(v)
			} else {
				tmpInstance.BinlogDir = filepath.Dir(ReadCfgFromFile(tmpInstance.MycnfFile, "log_bin"))
			}
			//error-log
			if v, ok := argsMap["log-error"]; ok {
				tmpInstance.ErrorLogFile = v
			} else if v, ok = argsMap["log_error"]; ok {
				tmpInstance.ErrorLogFile = v
			} else {
				tmpInstance.ErrorLogFile = ReadCfgFromFile(tmpInstance.MycnfFile, "log_error")
			}
			//SlowLogFile,如果不存在则检查看datadir目录下是否存在<hostname>-slow.log形式的慢日志文件
			if v, ok := argsMap["slow_query_log_file"]; ok {
				tmpInstance.SlowLogFile = v
			} else if v, ok = argsMap["slow-query-log-file"]; ok {
				tmpInstance.SlowLogFile = v
			} else {
				tmpInstance.SlowLogFile = ReadCfgFromFile(tmpInstance.MycnfFile, "slow_query_log_file")
			}
			//补充确认slowlog是否存在
			if _, err := os.Lstat(tmpInstance.SlowLogFile); err != nil {
				hostname, _ := os.Hostname()
				slowlog := filepath.Join(tmpInstance.DataDir, hostname+"-slow.log")
				if _, err := os.Lstat(slowlog); err == nil {
					tmpInstance.SlowLogFile = slowlog
				}
			}
			//查找port和socket file
			if v, ok := argsMap["port"]; ok {
				tmpInstance.Port, _ = strconv.Atoi(v)
			}
			if v, ok := argsMap["socket"]; ok {
				tmpInstance.SocketFile = v
			}
			if tmpInstance.Port == 0 || tmpInstance.SocketFile == "" {
				//从进程的网络监听端口层面来确认端口号，需要root权限
				if netstats, err := p.Connections(); err == nil {
					for _, netstat := range netstats {
						if netstat.Status == "LISTEN" {
							if tmpInstance.Port == 0 {
								tmpInstance.Port = int(netstat.Laddr.Port)
							} else if tmpInstance.Port > int(netstat.Laddr.Port) {
								tmpInstance.Port = int(netstat.Laddr.Port)
							}
						} else if netstat.Status == "NONE" && strings.HasSuffix(netstat.Laddr.IP, "sock") {
							tmpSocketFile := netstat.Laddr.IP
							if tmpInstance.SocketFile == "" {
								tmpInstance.SocketFile = tmpSocketFile
							} else if len(filepath.Base(tmpInstance.SocketFile)) > len(filepath.Base(tmpSocketFile)) {
								tmpInstance.SocketFile = tmpSocketFile
							}
						}
					}
				}
			}
			//进一步判断tmpInstance.Port是否为0，如果还是为0则查找my.cnf文件
			if tmpInstance.Port == 0 {
				tmpPort := ReadCfgFromFile(tmpInstance.MycnfFile, "port")
				if tmpPort != "" {
					if _port, err := strconv.Atoi(tmpPort); err == nil {
						tmpInstance.Port = _port
					}
				} else {
					tmpInstance.Port = 3306 //最后赋予默认值
				}
			}
			if tmpInstance.SocketFile == "" {
				_socket := ReadCfgFromFile(tmpInstance.MycnfFile, "socket")
				if _socket != "" {
					tmpInstance.SocketFile = _socket
				}
			}
			//获取版本信息
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
			defer cancel()
			cmd := exec.CommandContext(ctx, strings.TrimSuffix(tmpInstance.FullName, "d"), "--version", "--verbose")
			if output, err := cmd.CombinedOutput(); err == nil {
				tmpInstance.VersonInfo = string(output)
				re := regexp.MustCompile(`\s+(\d+\.\d+\.\d+)\s+`)
				subMatchs := re.FindStringSubmatch(tmpInstance.VersonInfo)
				for _, m := range subMatchs {
					tmpInstance.Verson = m
				}
			}
			mysqlInstanceList = append(mysqlInstanceList, *tmpInstance)
		}
	}
	return mysqlInstanceList
}

//解析my.cnf文件
func ReadCfgFromFile(filename string, key string) string {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Loose:                   true,
		SkipUnrecognizableLines: true,
		AllowBooleanKeys:        true,
		ReaderBufferSize:        0,
	}, filename)

	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return ""
	}
	if val := cfg.Section("mysqld").Key(key).String(); val != "" {
		return val
	} else if val = cfg.Section("mysqld").Key(strings.ReplaceAll(key, "-", "_")).String(); val != "" {
		return val
	} else if val = cfg.Section("mysqld").Key(strings.ReplaceAll(key, "_", "-")).String(); val != "" {
		return val
	}
	return ""
}
