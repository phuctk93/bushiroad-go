package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
	"github.com/teris-io/shortid"
)

var (
	pdb    *pg.DB
	admin  = map[string]string{}
	secret = []byte("YouCanSeeThis")
)

//User is struct of players
type User struct {
	ID       int       `json:"id,omitempty"`
	Key      string    `json:"key,omitempty"`
	Score    int       `json:"score,omitempty"`
	Rank     int       `json:"rank,omitempty"`
	Name     string    `sql:"default:'Anonymous'" json:"name,omitempty"`
	Emai     string    `json:"email,omitempty"`
	Registed time.Time `json:"reg,omitempty"`
	Esign    bool      `json:"esign,omitempty"`
}

//Admin is struct of admin user
type Admin struct {
	Name string `json:"name,omitempty"`
	Pass string `json:"pass,omitempty"`
}

//Data is struct of database config
type Data struct {
	Network  string `json:"network,omitempty"`
	Address  string `json:"address,omitempty"`
	DataName string `json:"data_name,omitempty"`
	User     string `json:"user,omitempty"`
	Pass     string `json:"pass,omitempty"`
}

//Config is struct of config.json
type Config struct {
	Admin    []Admin  `json:"admin,omitempty"`
	Host     []string `json:"hosts,omitempty"`
	Database Data     `json:"database,omitempty"`
	Example  bool     `json:"example,omitempty"`
	TLS      bool     `json:"tls,omitempty"`
	Cert     string   `json:"cert,omitempty"`
	Key      string   `json:"key,omitempty"`
}

func main() {
	js, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Panic(err)
	}
	config := Config{}
	err = json.Unmarshal(js, &config)
	if err != nil {
		log.Panic(err)
	}
	pdb = pg.Connect(&pg.Options{
		Network:  config.Database.Network,
		Addr:     config.Database.Address,
		User:     config.Database.User,
		Password: config.Database.Pass,
		Database: config.Database.DataName,
	})
	defer pdb.Close()

	for _, ad := range config.Admin {
		admin[ad.Name] = ad.Pass
	}

	// Create table
	pdb.CreateTable(&User{}, &orm.CreateTableOptions{
		IfNotExists: true,
	})

	// Create some records
	if config.Example {
		now := time.Now()
		for i := 0; i < 10; i++ {
			key, _ := shortid.Generate()
			u := User{
				Key:      key,
				Name:     fmt.Sprintf("BushiRoad_%v", i),
				Score:    10 + 10*i,
				Registed: now,
			}
			pdb.Insert(&u)
		}
		log.Println("Inserted example")
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     config.Host,
		AllowMethods:     []string{"GET", "POST", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	a := r.Group("/adm").Use(checkJWT())
	{
		a.GET("/list", listHandler)
		a.GET("/export", exportHandler)
	}

	r.POST("/login", loginHandler)
	r.POST("/submit", submitHandler)
	r.POST("/rank", getRank)
	r.GET("/lb", leaderBoardHandler)

	if config.TLS {
		r.RunTLS(":5000", config.Cert, config.Key)
	} else {
		r.Run(":5000")
	}

}

func loginHandler(c *gin.Context) {
	user := Admin{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		log.Println(err)
		c.String(500, err.Error())
		return
	}
	if user.Name == "" {
		c.String(401, "Please enter name")
		return
	}
	if user.Pass == "" {
		c.String(401, "Please enter pass")
		return
	}

	pass, ok := admin[user.Name]
	if !ok {
		c.String(404, "Wrong user name! Please try again")
		return
	}
	if pass != user.Pass {
		c.String(404, "Wrong pass! Please try again")
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		log.Println(err)
		c.String(500, err.Error())
		return
	}
	c.String(200, tokenString)
}

func listHandler(c *gin.Context) {
	limit, offset := getQuery(c)
	list := []User{}
	_, err := pdb.Query(&list, `SELECT *,
	row_number() OVER (ORDER BY score DESC) as rank
	FROM users
	ORDER BY id DESC
	OFFSET ? LIMIT ?`, offset, limit)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't get list top 100 user")
		return
	}
	c.JSON(200, list)
}

func exportHandler(c *gin.Context) {
	header := []string{
		"S/N", "Score", "Current Position", "Name", "Email Adresses", "Date/Time Registed", "E-Letter sign up",
	}
	users := []User{}
	_, err := pdb.Query(&users, `SELECT * FROM users`)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't get all record")
		return
	}
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment;filename=all.csv")
	//b := &bytes.Buffer{}
	w := csv.NewWriter(c.Writer)
	err = w.Write(header)
	if err != nil {
		c.String(500, "Error sending csv: %v", err.Error())
		return
	}
	for _, u := range users {
		record := []string{
			fmt.Sprint(u.ID),
			fmt.Sprint(u.Score),
			fmt.Sprint(u.Rank),
			u.Name,
			u.Emai,
			fmt.Sprint(u.Registed),
			fmt.Sprint(u.Esign),
		}
		err = w.Write(record)
		if err != nil {
			break
		}
	}
	if err != nil {
		c.String(500, "Error sending csv: %v", err.Error())
		return
	}
	w.Flush()

	//c.Data(200, "text/csv", b.Bytes())
}

func submitHandler(c *gin.Context) {
	user := User{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't decode json")
		return
	}
	if user.Name == "" {
		c.String(400, "Please enter your name")
		return
	}

	if user.Emai == "" {
		c.String(400, "Please enter your email")
		return
	}

	if user.Key == "" {
		key, err := shortid.Generate()
		if err != nil {
			log.Println(err)
			c.String(500, "Can't generate key")
			return
		}
		loc := time.FixedZone("UTC+8", 8*60*60)
		user.Key = key
		user.Registed = time.Now().In(loc)
		err = pdb.Insert(&user)
		if err != nil {
			log.Println(err)
			c.String(500, "Can't set user info")
			return
		}
	} else {
		_, err = pdb.ExecOne(`UPDATE users SET score = ? WHERE key = ?`, user.Score, user.Key)
		if err != nil {
			log.Println(err)
			c.String(500, "Can't update your score")
			return
		}
	}
	c.JSON(200, user)
}

func getRank(c *gin.Context) {
	var score int64
	err := c.ShouldBindJSON(&score)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't decode json")
		return
	}
	var rank int64
	_, err = pdb.QueryOne(&rank, `SELECT count(score) FROM users WHERE score > ?`, score)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't get rank")
		return
	}
	min := rank / 10
	min = min * 10
	list := []User{}
	_, err = pdb.Query(&list, `SELECT name, score, row_number() OVER (ORDER BY score DESC) as rank FROM users OFFSET ? LIMIT 10`, min)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't get list with rank")
		return
	}
	c.JSON(200, gin.H{
		"rank": rank,
		"list": list,
	})
}

func leaderBoardHandler(c *gin.Context) {
	list := []User{}
	_, err := pdb.Query(&list, `SELECT name, score FROM users ORDER BY score DESC OFFSET 0 LIMIT 10`)
	if err != nil {
		log.Println(err)
		c.String(500, "Can't get list top 10 user")
		return
	}
	c.JSON(200, list)
}

//Return Limit, Offset. Default: 100, 0
func getQuery(c *gin.Context) (int, int) {
	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil {
		log.Println(err)
		limit = 100
	}
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		log.Println(err)
		page = 1
	}
	offset := (page - 1) * limit
	return limit, offset
}

func checkJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			log.Println("No token!")
			c.AbortWithStatus(401)
			return
		}
		err := CheckTokenValid(token)
		if err != nil {
			log.Println(err)
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	}
}

//CheckTokenValid is check valid token, return boolean
func CheckTokenValid(myToken string) error {
	log.Println(myToken)
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		//secret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secret, nil
	})

	if err == nil && token.Valid {
		return nil
	}
	return err
}
