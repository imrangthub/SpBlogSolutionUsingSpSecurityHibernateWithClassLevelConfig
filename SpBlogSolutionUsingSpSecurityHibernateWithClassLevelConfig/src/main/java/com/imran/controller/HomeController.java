package com.imran.controller;

import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import com.imran.model.Post;
import com.imran.service.PostService;
import com.imran.service.TestService;


@Controller
public class HomeController {
	
//	@Autowired
//	PostService postService;
	
	@Autowired
	PostService postService;

	
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String index(ModelMap map) {
		
	
	
		List<Post> results = postService.postList();
		Post lastPost=null;
		if(!results.isEmpty()){
			Collections.reverse(results);
			lastPost = results.get(0);
			results.remove(0);
		}
		map.addAttribute("lastPost",lastPost);
		map.addAttribute("postList",results);
		return "home";
	}

}

