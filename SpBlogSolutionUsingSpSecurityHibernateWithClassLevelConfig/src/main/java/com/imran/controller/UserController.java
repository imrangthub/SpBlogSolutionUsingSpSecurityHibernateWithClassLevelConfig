package com.imran.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.imran.model.User;
import com.imran.service.PostService;
import com.imran.service.UserService;


@Controller
@RequestMapping(value = "/user")
public class UserController {
	
	@Autowired
	UserService userService;
	
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String index(Model model) {
		return "user/dashboard";
	}
	
	@RequestMapping(value = "/reg", method = RequestMethod.GET)
	public String registrationView(Model model) {
		return "user/registration";
	}
	
	@RequestMapping(value = "/reg", method = RequestMethod.POST)
	public String registration(Model model, @ModelAttribute("user") User user, BindingResult result) {
		int resultStatus = 0;  
		if(user.getEmail().isEmpty() || user.getPassword().isEmpty() || user.getGender().isEmpty() || user.getName().isEmpty()){
			  model.addAttribute("message", "Require field is Empty");
			  return "redirect:/user/reg";
			}
	  userService.userRegistration(user);
	  model.addAttribute("message", "Successfully registration Complete.");  
	  return "redirect:/user/reg";
	}
}

