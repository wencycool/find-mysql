package main

import (
	"encoding/json"
	"fmt"
)

func main()  {

	list := GetInstances()
	bs,_ := json.MarshalIndent(list," "," ")
	fmt.Println(string(bs))
}
