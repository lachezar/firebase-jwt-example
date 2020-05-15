# firebase-jwt-example

example verification of JWT from Firebase with Servant

```
curl -v -H 'Authorization: Bearer <JW TOKEN HERE>' 'http://localhost:3001/private/42'
```

To run the server you have to have `stack` installed

```
stack build
stack exec firebase-jwt-example-exe
```