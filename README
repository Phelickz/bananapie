Banana Pie Api Test using ExpressJS and Typescript.

## Installing

To run this project, clone this project.
Ensure you have NodeJs installed on your local machine.

## Usage

Run `npm install` to install all the required dependencies.
Then use `npm run dev` to start the project

There are three routes:
 -- `...signup [POST]`
 -- `...login  [POST]`
 -- `...users  [GET]`


# Sign Up

    POST /signup

### Body Parameters

| Name    | Type      | Description                          |
|---------|-----------|--------------------------------------|
| email			| String			|  <p>User email.</p>							|
| password			| String			|  <p>User's password.</p>							|

Returns json response of the `user`

# Login

    POST /login

### Body Parameters

| Name    | Type      | Description                          |
|---------|-----------|--------------------------------------|
| email			| String			|  <p>User email.</p>							|
| password			| String			|  <p>User's password.</p>							|

Returns json response of the `user`
Returns `Authorization Token, Refresh Token and CSRF token` in cookies, 


# Get User

    GET /users

### QUERY Parameters

| Name    | Type      | Description                          |
|---------|-----------|--------------------------------------|
| email			| String			|  <p>User email.</p>							|

### Body Parameters

| Name    | Type      | Description                          |
|---------|-----------|--------------------------------------|
| _csrf			| String			|  <p>CSRF token from login cookie.</p>							|


Returns json response of the `user`
Returns `CSRF token` in cookies, 