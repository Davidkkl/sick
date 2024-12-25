package models

import (
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Account  string `json:"account"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func Register(user *User) (err error) {
	// 对传入的密码进行哈希加密
	// []byte(user.Password) 将其转换为字节切片。
	//第二个参数: 这是加密的成本 (cost) 值。bcrypt.DefaultCost 是 bcrypt 的默认成本参数，通常设为 10。成本越高，计算所需的时间越长，加密过程就越慢，但安全性也相应提高。
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 将加密后的密码存入 user 结构体
	user.Password = string(hashedPassword)

	// 将用户数据存入数据库
	if err = DB.Create(&user).Error; err != nil {
		return err
	}
	return
}

func GetUserByAccount(account string) (User, error) {
	var user User
	if err := DB.Where("account = ?", account).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}
