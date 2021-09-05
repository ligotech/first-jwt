package com.jwt.learning.firstjwt.users;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController()
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user){
        //try{
            User user1 = userService.save(user);
            if(user1 != null){
                return new ResponseEntity<>(user1.getUsername(), HttpStatus.CREATED);
            }
        //}
        //catch (Exception ex) {
            throw new RuntimeException("User creation failed");
        //}

    }
}
