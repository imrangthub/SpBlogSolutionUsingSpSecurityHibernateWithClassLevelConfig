package com.imran.common;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import javax.servlet.http.HttpSession;

import org.springframework.web.multipart.MultipartFile;

import com.imran.model.User;


public class BaseService{
	
	
   public User getCurrentUserInfo( HttpSession session){
	   User user = (User)session.getAttribute("loginUser");
	   if(user !=null){
			  System.out.println("From Base Service Email from Session: " + user.getEmail());
	   }
	  return user;
   }

	public boolean removeFile(String fileName) {
		File file = new File(
				"G:/1_BlogWithSpringSolution/Pro3/BlogSolutionUsingSpringHibernateWithXmlConfig/src/main/webapp/resources/imgFolder/"
						+ fileName);
		return file.delete();
	}

	public Boolean checkFile(MultipartFile file) {
		boolean fileExtCheck = false;
		try {
			byte[] bytes = file.getBytes();
			String fileName = file.getOriginalFilename();

			String[] fileExt = { ".jpg", ".png", ".jpeg" };
			int IndexOf = fileName.indexOf(".");
			String currentImgExt = fileName.substring(IndexOf);
			System.out.println("Current imag formate: " + currentImgExt);
			fileExtCheck = Arrays.asList(fileExt).contains(currentImgExt);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return fileExtCheck;
	}

	public String uploadFileName(MultipartFile file) {
		String uniqName = null;

		byte[] bytes;
		try {
			bytes = file.getBytes();

			String fileName = file.getOriginalFilename();

			Random generator = new Random();
			int r = Math.abs(generator.nextInt());
			uniqName = r + "_" + (String) fileName;
			File dir = new File(
					"G:/1_BlogWithSpringSolution/Pro3/BlogSolutionUsingSpringHibernateWithXmlConfig/src/main/webapp/resources/imgFolder/");
			// Create the file on server
			File serverFile = new File(dir.getAbsolutePath() + File.separator + uniqName);
			BufferedOutputStream stream = new BufferedOutputStream(new FileOutputStream(serverFile));
			stream.write(bytes);
			stream.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return uniqName;
	}

}
