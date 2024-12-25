package routers

import (
	"github.com/gin-gonic/gin"
	"sick/controller"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")
	r.GET("/", controller.IndexHandler)

	r.GET("/result", controller.Result)

	r.POST("/register", controller.Register)

	r.POST("/login", controller.Login)
	//邮箱发送验证码
	r.POST("/send-email", controller.SendEmailHandler)

	//验证验证码
	r.POST("/verify", controller.VerifyCodeHandler)

	r.POST("/question", controller.Question)
	return r
}
