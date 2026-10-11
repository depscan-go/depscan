module example.com/vuln-go

go 1.22

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // HIGH: GHSA-w73w-5m7g-f7qc (also listed as GO-2020-0017)
	github.com/gin-gonic/gin v1.9.0 // MODERATE: GHSA-2c4m-59x9-fr2g (also listed as GO-2023-1737)
)
