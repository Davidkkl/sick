package models

import (
	"gorm.io/gorm"
)

type Message struct {
	ID                 int `json:"id"`
	Gender             int `json:"gender"`
	EduLevel           int `json:"eduLevel"`
	Smoking            int `json:"smoking"`
	Alcohol            int `json:"alcohol"`
	SleepQuality       int `json:"sleepQuality"`
	FamHistAlz         int `json:"famHistAlz"`
	CVD                int `json:"CVD"`
	Diabetes           int `json:"diabetes"`
	Depression         int `json:"depression"`
	HeadInjury         int `json:"headInjury"`
	Hypertension       int `json:"hypertension"`
	BehavioralIssues   int `json:"behavioralIssues"`
	Confusion          int `json:"confusion"`
	Disorientation     int `json:"disorientation"`
	PersonalityChanges int `json:"personalityChanges"`
	TaskDifficulty     int `json:"taskDifficulty"`
}

var (
	DB *gorm.DB
)

func CreateMessage(user *Message) (err error) {
	if err = DB.Create(&user).Error; err != nil {
		return err
	} else {
		return
	}
}
