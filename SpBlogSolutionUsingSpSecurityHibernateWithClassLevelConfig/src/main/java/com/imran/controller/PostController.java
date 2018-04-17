package com.imran.controller;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.imran.model.Post;
import com.imran.service.PostService;

@Controller
@RequestMapping(value = "/post")
public class PostController {

	@Autowired
	PostService postService;

	private static final String UPLOAD_DIRECTORY = "/imgFolder";

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String dashboard(ModelMap map) {
		List<Post> postList = postService.postList();
		Collections.reverse(postList);
		map.addAttribute("postList", postList);
		return "post/dashboard";
	}

	@RequestMapping(value = "/create", method = RequestMethod.GET)
	public String viewCreate(Model model, final RedirectAttributes redirectAttributes) {
//		redirectAttributes.addFlashAttribute("css", "success");
//		redirectAttributes.addFlashAttribute("message", "User added successfully!");
//		model.addAttribute("message", "Username or password is wrong.");
		return "post/create";
	}

	@RequestMapping(value = "/create", method = RequestMethod.POST)
	public String createPost(ModelMap map, @RequestParam("file") MultipartFile file,
			@RequestParam("title") String title, @RequestParam("body") String body) throws Exception {
		Post post;
		if (title.equals("") || body.equals("")) {
			map.addAttribute("message", "Require field  Template is Empty");
			return "post/create";
		}
		if (!file.getOriginalFilename().equals("")) {
			boolean imageFormateCheck = postService.checkFile(file);

			if (!imageFormateCheck) {
				map.addAttribute("message", "Invalid file formate");
				return "post/create";
			}
			String uploadedFileName = postService.uploadFileName(file);
			if (uploadedFileName != null) {
				post = new Post(title, body,uploadedFileName);
				postService.createOrUpdatePost(post);
			}

		} else {
			post = new Post(title, body,"");
            postService.createOrUpdatePost(post);
		}

		map.addAttribute("message", "Post Template added Successfully");
		return "post/create";

	}
	
	@RequestMapping(value="/edit/{id}")
	public String editView(ModelMap map, @PathVariable("id") long id){
		Post singlePost =  postService.findByPostId(id);
		if(singlePost == null){
			map.addAttribute("message", "Post not found");	
			return "redirect:/post/";
		}
		map.put("singlePost",singlePost);
		return "post/edit";
	}
	
	@RequestMapping(value = "/update", method = RequestMethod.POST)
	public String updatePost(ModelMap map, @RequestParam("file") MultipartFile file,
			@RequestParam("title") String title, @RequestParam("body") String body, @RequestParam("id") long id, @RequestParam("current_image") String current_image) throws Exception {
        Post post;
		if (title.equals("") || body.equals("")) {
			map.addAttribute("message", "Require field is Empty");
			return "post/create";
		}
		if(!current_image.equals("")){
			if (!file.getOriginalFilename().equals("")) {
				//
				boolean imageFormateCheck = postService.checkFile(file);
				if (!imageFormateCheck) {
					map.addAttribute("message", "Invalid file formate");
					return "post/create";
				}
				String uploadedFileName = postService.uploadFileName(file);
				if (uploadedFileName != null) {
					post = new Post(id, title, body, uploadedFileName, 1);
				    postService.updateProduct(post);
				    postService.removeFile(current_image);
				    map.addAttribute("message", "Post Update Successfully");
					return "post/create";
				}

			} else {
				post = new Post(id, title, body, current_image, 1);
	            postService.updateProduct(post);
	            map.addAttribute("message", "Post Update Successfully");
				return "post/create";
			}
		}else{
			post = postService.findByPostId(id);
			postService.removeFile(post.getFeature_image());
		}

		if (!file.getOriginalFilename().equals("")) {
			//
			boolean imageFormateCheck = postService.checkFile(file);
			if (!imageFormateCheck) {
				map.addAttribute("message", "Invalid file formate");
				return "post/create";
			}
			String uploadedFileName = postService.uploadFileName(file);
			if (uploadedFileName != null) {
				post = new Post(id, title, body, uploadedFileName, 1);
			    postService.updateProduct(post);
			}

		} else {
			post = new Post(id, title, body, "", 1);
		    postService.updateProduct(post);
		}

		map.addAttribute("message", "Post Update Successfully");
		return "post/create";

	}

	@RequestMapping(value = "/delete/{id}")
	public String delete(ModelMap map, @PathVariable("id") Integer id) {
        postService.removeProduct(id);
		map.put("message", "Successfully Delete this Post");
		return "redirect:/post/";
	}

}
