# syra-login-go

This is scratch project for syra login, painstakingly implemented in go and noir. For production, need to implement it in js+noir


ZK Circuit for Generating the Prove : https://github.com/pamungkaski/syra-login/tree/main/zk/syra_login

To innitate login,
```
go run initiate_google/main.go
```

then copy your jwt to main.go
```
jwtToken := <YOUR-JWT>
```

then to create witness and prove, run

```
go run main.go
```

it will create proof inside /zk/syra_login/target
