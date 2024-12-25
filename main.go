package main

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"sick/models"
	"sick/routers"
)

func main() {
	var err error
	// 替换为你的数据库连接信息
	dsn := "root:13538813411@tcp(127.0.0.1:3306)/sick?charset=utf8mb4&parseTime=True&loc=Local"
	models.DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	r := routers.SetupRouter()
	r.Run(":9092")
}
