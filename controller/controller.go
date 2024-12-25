package controller

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"io"
	"math/big"
	"net/http"
	"net/smtp"
	"net/url"
	"sick/models"
	"sync"
	"time"
)

func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func Result(c *gin.Context) {
	// 获取查询参数
	result := c.Query("result")

	// 渲染 result.html 模板，并将数据传递过去
	c.HTML(http.StatusOK, "result.html", gin.H{
		"Result": result,
	})
}

// 用于存储验证码的全局变量 (简单缓存机制)
var verificationCodes = make(map[string]string)
var mutex = &sync.Mutex{}

type ChatResponse struct {
	Response string `json:"response"`
}

var str string

// Check 函数用于返回 0 或 1，判断输入数字是否为 0
func Check(number int) int {
	if number == 0 {
		return 0
	}
	return 1
}

func Connect(message string) (string, error) {
	baseURL := "http://192.168.43.135:8000/chat"

	str = ""

	//message = ""
	//有心脏病，有迷失方向，有上过大学，有吸过烟，有每周喝五次酒，有行为问题，存在模糊意识，有性格变化，我是女性，有抑郁症，有头部外伤史，有失眠，有家族阿尔海默症，能正常生活。没有糖尿病，请判断我是否有阿尔海默症。//回复
	//有心脏病，有迷失方向，有上过大学，有吸过烟，有每周喝五次酒，有行为问题，存在模糊意识，有性格变化，我是女性，有抑郁症，有头部外伤史，有失眠，有家族阿尔海默症，能正常生活。没有糖尿病，请判断我是否有阿尔海默兹症 //不回复
	//message = "有心脏病，有迷失方向，有上过大学，有吸过烟，有每周喝五次酒，有行为问题，存在模糊意识，有性格变化，我是女性，有抑郁症，有头部外伤史，有失眠，有家族阿尔海默症，能正常生活。没有糖尿病，请判断我是否有阿尔海默症。"
	//fmt.Println(message)

	// 将消息进行URL编码
	encodedMessage := url.QueryEscape(message)
	//fmt.Println(message)
	finalURL := fmt.Sprintf("%s?message=%s", baseURL, encodedMessage)
	//fmt.Println(finalURL)

	// 发送GET请求
	resp, err := http.Get(finalURL)
	if err != nil {
		return "", fmt.Errorf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	//fmt.Println(respBytes)
	if err != nil {
		return "", fmt.Errorf("Error reading response: %v", err)
	}
	//fmt.Println(string(respBytes))
	//fmt.Println(respBytes)
	// 解析json数据
	var chatResp ChatResponse
	err = json.Unmarshal(respBytes, &chatResp)

	if err != nil {
		return "", fmt.Errorf("Error unmarshaling response: %v", err)
	}
	// 返回解析后的响应
	//formattedResponse := strings.ReplaceAll(chatResp.Response, "\\n", "\n")
	//fmt.Println(chatResp.Response)
	return chatResp.Response, nil
}

// modifyDesc 函数用于修改某些描述的肯定形式
func modifyDesc(desc string) string {
	switch desc {
	case "我是男性，":
		return "我是女性，"
	case "没有上过大学，":
		return "有上过大学，"
	case "没有吸过烟，":
		return "有吸过烟，"
	case "没有每周喝五次酒，":
		return "有每周喝五次酒，"
	case "没有失眠，":
		return "有失眠，"
	case "没有家族阿尔兹海默症，":
		return "有家族阿尔兹海默症，"
	case "没有心脏病，":
		return "有心脏病，"
	case "有糖尿病，":
		return "没有糖尿病，"
	case "没有抑郁症，":
		return "有抑郁症，"
	case "没有头部外伤史，":
		return "有头部外伤史，"
	case "没有行为问题，":
		return "有行为问题，"
	case "不存在模糊意识，":
		return "存在模糊意识，"
	case "没有迷失方向，":
		return "有迷失方向，"
	case "没有性格变化，":
		return "有性格变化，"
	case "不能正常生活。":
		return "能正常生活。"
	default:
		return desc
	}
}

// Question 函数用于生成基于用户输入的信息字符串并创建用户记录
func Question(c *gin.Context) {
	var user models.Message
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//str += "请判断我是否有阿尔兹海默症,"

	fieldMap := map[string]int{
		"我是男性，":       user.Gender,
		"没有上过大学，":     user.EduLevel,
		"没有吸过烟，":      user.Smoking,
		"没有每周喝五次酒，":   user.Alcohol,
		"没有失眠，":       user.SleepQuality,
		"没有家族阿尔兹海默症，": user.FamHistAlz,
		"没有心脏病，":      user.CVD,
		"有糖尿病，":       user.Diabetes,
		"没有抑郁症，":      user.Depression,
		"没有头部外伤史，":    user.HeadInjury,
		"没有行为问题，":     user.BehavioralIssues,
		"不存在模糊意识，":    user.Confusion,
		"没有迷失方向，":     user.Disorientation,
		"没有性格变化，":     user.PersonalityChanges,
		"不能正常生活。":     user.TaskDifficulty,
	}

	// 根据每个字段的值拼接相应的描述
	for desc, value := range fieldMap {
		if Check(value) == 0 {
			str += desc
		} else {
			// 若为 1 则更改对应的描述（仅适用于特定字段）
			str += modifyDesc(desc)
		}
	}

	str += "请判断我是否有阿尔兹海默症。"

	respone, err := Connect(str)
	//fmt.Println(1)
	//respone = strings.Replace(result)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 创建用户记录并返回相应的响应
	if err := models.CreateMessage(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
	} else {
		c.JSON(http.StatusOK, respone)
	}
}

func Register(c *gin.Context) {
	var user models.User
	c.BindJSON(&user)
	//// 比较两次输入的密码是否一致
	//if user.Password != user.ConfirmPassword {
	//	c.JSON(http.StatusBadRequest, gin.H{
	//		"error": "Passwords do not match",
	//	})
	//	return
	//}
	err := models.Register(&user)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
	} else {
		c.JSON(http.StatusOK, user)
	}
}

//用户登录

// 定义JWT的密钥，确保这个密钥足够复杂和保密
var jwtSecret = []byte("wdw")

// 定义JWT的声明（Claims），可以添加自定义字段
type Claims struct {
	Account            string `json:"account"` // 用于存储用户账号
	jwt.StandardClaims        // 内嵌的标准声明，例如过期时间、发放时间等
}

func Login(c *gin.Context) {
	var input models.User
	if err := c.BindJSON(&input); err != nil {
		// 如果解析JSON失败，返回错误响应
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// 根据账号从数据库中查找用户
	user, err := models.GetUserByAccount(input.Account)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)) != nil {
		// 如果账号不存在或密码不匹配，返回错误响应
		c.JSON(http.StatusUnauthorized, gin.H{"error": "账号或密码错误"})
		return
	}

	// 如果账号和密码正确，生成JWT
	expirationTime := time.Now().Add(24 * time.Hour) // 设置JWT的过期时间为24小时
	claims := &Claims{
		Account: input.Account, // 将用户的账号存入声明
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(), // 设置Token的过期时间
		},
	}

	// 创建Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret) // 使用密钥签名生成Token
	if err != nil {
		// 如果生成Token失败，返回错误响应
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成Token"})
		return
	}

	// 返回Token给客户端
	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenString, // 返回生成的JWT
	})
}

func sendEmail(to string, subject string, body string) error {
	from := "1241570058@qq.com"
	password := "hnolquzanwscgbah" //申请的密码

	// SMTP服务器信息
	smtpHost := "smtp.qq.com"
	smtpPort := "587"

	// 设置认证信息
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// 邮件内容
	message := []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body + "\r\n")

	// 发送邮件
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, message)
	if err != nil {
		return err
	}

	return nil
}

func GenerateVerificationCode(length int) (string, error) {
	var code string
	for i := 0; i < length; i++ {
		// 生成一个0-9的随机数
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		// 将数字转为字符串并追加到验证码
		code += n.String()
	}
	return code, nil
}

func SendEmailHandler(c *gin.Context) {
	//c.HTML(http.StatusOK, "index.html", nil)

	type Email struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
	}

	var email Email
	if err := c.BindJSON(&email); err != nil {
		// 如果解析JSON失败，返回错误响应
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	//生成验证码
	code, err := GenerateVerificationCode(6)
	if err != nil {
		fmt.Println("生成验证码时出错:", err)
		return
	}

	// 将验证码缓存起来（与邮箱绑定）
	mutex.Lock()
	verificationCodes[email.To] = code
	mutex.Unlock()

	//fmt.Println("生成的验证码:", code)

	body := "验证码：" + code + "\n" + "请在5分钟内验证！"

	err = sendEmail(email.To, email.Subject, body)
	if err != nil {
		c.JSON(500, gin.H{"status": "Error", "message": err.Error()})
		return
	}

	// 设置5分钟后删除验证码
	go func(email string) {
		time.Sleep(5 * time.Minute)
		mutex.Lock()
		delete(verificationCodes, email)
		mutex.Unlock()
	}(email.To)

	c.JSON(http.StatusOK, gin.H{"status": "Success", "message": "邮件成功发送！"})

}

// VerifyCodeHandler 用于验证验证码的处理函数
func VerifyCodeHandler(c *gin.Context) {
	type Verification struct {
		To   string `json:"to"`
		Code string `json:"code"`
	}

	var v Verification
	if err := c.BindJSON(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// 检查验证码
	mutex.Lock()
	storedCode, exists := verificationCodes[v.To]
	mutex.Unlock()

	if !exists || storedCode != v.Code {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "验证码无效或已过期"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "Success", "message": "验证码验证成功"})
}
