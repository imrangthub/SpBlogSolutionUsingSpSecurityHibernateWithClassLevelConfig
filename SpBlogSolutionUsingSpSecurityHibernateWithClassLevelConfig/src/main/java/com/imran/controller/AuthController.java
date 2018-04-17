package com.imran.controller;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestParam;

import com.imran.model.User;
import com.imran.service.UserService;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


@Controller
@RequestMapping(value = "/auth")
public class AuthController {
	
	@Autowired
	UserService userService;
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String loginView(Model model) {
		return "user/login";
	}
		
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String login(HttpSession session, Model model, @RequestParam("email") String email, @RequestParam("password") String password) {
		 User loginUser = null; ;
		if(email.equals("") || password.equals("")){
			  model.addAttribute("message", "Require field is Empty");
				return "redirect:/auth/login";
			}
		loginUser = userService.userLogin(email, password);
		if(loginUser != null){
		    session.setAttribute("loginUser", loginUser);
			model.addAttribute("message", "Successfully Login complete");
			return "redirect:/user/";	
		} 
		model.addAttribute("message", "User not found.!");
		return "user/login";
	}
	

   @GetMapping("/logout")
   public String logout(HttpSession session ) {
      session.invalidate();
      return "redirect:/auth/login";
   }
}
