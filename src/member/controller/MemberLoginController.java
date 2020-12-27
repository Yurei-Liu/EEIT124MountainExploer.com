package member.controller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import member.MemberGlobal;
import member.model.MemberBasic;
import member.model.MemberService;

@Controller
@SessionAttributes(names = {"Member", "beforeCheckURL"})
public class MemberLoginController {

	private static String beforeCheckURL;
	
	
	@Autowired
	private MemberService mbService;

	
	@RequestMapping(path = "/member/memberLoginEntry", method = RequestMethod.GET)
	public String processLoginEntry() {
		return "member/formalLoginPage";
	}	
	
	
	//topbar顯示
	@ResponseBody
	@GetMapping(path = "/member/memberChkLogin")
	public boolean processchkLogin(Model m) {
		if(m.getAttribute("Member") != null) {
			return true;
		}else {
			return false;
		}
	}
	
	@ResponseBody
	@GetMapping(path = "/member/getSession")
	public List<MemberBasic> processGetSession(HttpSession httpSession) {
		MemberBasic mb = (MemberBasic) httpSession.getAttribute("Member");
		int seqno = mb.getSeqno();
		List<MemberBasic> mbList = mbService.selectInfo(seqno);
		return mbList;
	}
	
	
	//一般登山者快速登入
	@ResponseBody
	@GetMapping(value = "/member/FastLoginOne")
	public boolean processFastLogin1(@RequestParam(name = "userLog1")String userLog1,
									Model m) {
		if(userLog1 != null) {
			MemberBasic mb = mbService.select(1000000);
			m.addAttribute("Member", mb);			
			return true;
		}
		return false;
		
	}
	
	
	//登山嚮導快速登入
	@ResponseBody
	@GetMapping(value = "/member/FastLoginTwo")
	public boolean processFastLogin2(@RequestParam(name = "userLog2")String userLog2,
									 Model m) {
		if(userLog2 != null) {
			MemberBasic mb = mbService.select(1000004);
			m.addAttribute("Member", mb);
			return true;
		}
		return false;
	}
	
	
	//管理員快速登入
	@ResponseBody
	@GetMapping(value = "/member/FastLoginAdmin")
	public boolean processFastLogin3(@RequestParam(name = "adminLog")String adminLog,
							 			Model m) {
		if(adminLog != null) {
			MemberBasic mb = mbService.select(1000010);
			m.addAttribute("Member", mb);
			return true;
		}
		return false;
	}
	
	
	//登入
	@ResponseBody
	@GetMapping(path = "/member/memberLogin")
	public int processCheckLogin(
			@RequestParam(name = "account")String account,
			@RequestParam(name = "password")String password,
			@RequestParam(name = "rememberMe", required = false)String rm,
			HttpServletResponse response,
			Model m,
			RedirectAttributes redAttr) {
		
		System.out.println("========================rememberMe:" + rm);
		
		Map<String, String> errors = new HashMap<String, String>();
		m.addAttribute("errors", errors);
		
		if(m.getAttribute("beforeCheckURL") != null) {
			beforeCheckURL = (String)m.getAttribute("beforeCheckURL");
			System.out.println("beforeCheckURL : " + beforeCheckURL);
		}
			
		if(errors != null && !errors.isEmpty()) {
			return 0;
		}
		
		
		if(rm != "") {
			System.out.println("A");
			Cookie cookieAnt = new Cookie("rmAnt", account);
			cookieAnt.setMaxAge(30*24*60*60);
			cookieAnt.setPath("/");
			
			String ckPwd = MemberGlobal.encryptString(password);
			Cookie cookiePwd = new Cookie("rmPwd", ckPwd);
			cookiePwd.setMaxAge(30*24*60*60);
			cookiePwd.setPath("/");
			
			String rmCk = "check";
			Cookie cookieRm = new Cookie("rememberMe", rmCk);
			cookieRm.setMaxAge(30*24*60*60);
			cookieRm.setPath("/");
			
			response.addCookie(cookieAnt);
			response.addCookie(cookiePwd);
			response.addCookie(cookieRm);
			
		} else {
			System.out.println("B");
			Cookie cookieAnt = new Cookie("rmAnt", "");
			cookieAnt.setMaxAge(0);
			cookieAnt.setPath("/");
			
			String ckPwd = MemberGlobal.encryptString(password);
			Cookie cookiePwd = new Cookie("rmPwd", "");
			cookiePwd.setMaxAge(0);
			cookiePwd.setPath("/");
			
			Cookie cookieRm = new Cookie("rememberMe", "");
			cookieRm.setMaxAge(0);
			cookieRm.setPath("/");
			
			response.addCookie(cookieAnt);
			response.addCookie(cookiePwd);
			response.addCookie(cookieRm);
		}
		
		
		String pwdEN = MemberGlobal.getSHA1Endocing(MemberGlobal.encryptString(password));
		System.out.println("加密:" + pwdEN);
			
		if(account != null && password != null && errors.isEmpty()) {
			MemberBasic mb = mbService.checkPassword(account, pwdEN);
			if(mb != null) {
				if(mb.getMemberStatus().getSeqno() == 100 || mb.getMemberStatus().getSeqno() == 120) {
					m.addAttribute("Member", mb);
//					m.addAttribute("result", "登入成功");
					System.out.println("=======================登入成功");
					return mb.getMemberStatus().getSeqno();
				}else if(mb.getMemberStatus().getSeqno() == 110 || mb.getMemberStatus().getSeqno() == 130) {
					m.addAttribute("Member", mb);
//					m.addAttribute("result", "初次登入成功");
					System.out.println("=======================登入成功");
					return mb.getMemberStatus().getSeqno();
				}else if(mb.getMemberStatus().getSeqno() == 140 || mb.getMemberStatus().getSeqno() == 150) {
					return mb.getMemberStatus().getSeqno();
				}else if(mb.getMemberStatus().getSeqno() == 160) {
					m.addAttribute("Member", mb);
					return mb.getMemberStatus().getSeqno();
				}else {
					System.out.println("身分組權限不足");
					return 0;
				}
			} else {
				System.out.println("登入出錯");
				return 0;
			}
		}
		System.out.println("登入出錯");
		return 0;
		
	}
	

	
	//讀取cookie
	@ResponseBody
	@GetMapping(path =  "/member/cookieSelect")
	public Map<String, String> ReadCookieMap(HttpServletRequest request) {
		Map<String, String> cookieMap = new HashMap<String, String>();
		String value1 = "";
		String value2 = "";
		String value3 = "";
		Cookie[] cookies = request.getCookies();
		if(null != cookies) {
			for (Cookie cookie : cookies) {
				if(cookie.getName().equals("rmAnt")) {
					value1 = cookie.getValue();
					cookieMap.put("rmAnt", value1);
					System.out.println(value1);
				}
				if(cookie.getName().equals("rmPwd")) {
					value2 = MemberGlobal.decryptString(MemberGlobal.KEY, cookie.getValue());
					cookieMap.put("rmPwd", value2);
					System.out.println(value2);
				}
				if(cookie.getName().equals("rememberMe")) {
					value3 = cookie.getValue();
					if(value3 != null) {
						cookieMap.put("rememberMe", value3);						
						System.out.println(value3);
					} else {
						value3 = null;
						cookieMap.put("rememberMe", value3);
						System.out.println(value3);
					}
				}
			}
			return cookieMap;
		}else {
			return null;
		}
	}

	
	//登出
	@RequestMapping("/member/memberLogout")
	public String processLogout(
			HttpSession session, HttpServletRequest request, HttpServletResponse response, SessionStatus status) {
		session.removeAttribute("Member");
		status.setComplete();
		return "redirect:/";
	}
	
	
	//FB快速登入
	@RequestMapping(value = "/member/userInfo")
	@ResponseBody
	public int getFbUserInfo(String name, String email, Model m) {
		
		Map<String, String> errors = new HashMap<String, String>();
		m.addAttribute("errors", errors);
		
		System.out.println("==========name:" + name);
		System.out.println("==========email:" + email);
		
		MemberBasic mQuery = mbService.select(email);
		if(mQuery != null) {
			m.addAttribute("Member", mQuery);
			System.out.println("=======================登入成功");
			return 1;
		} else {
			
			MemberBasic mb = new MemberBasic();
			mb.setAccount(email);
			mb.setName(name);
			mb.setEmail(email);
			
			m.addAttribute("Member", mb);
			
			System.out.println("=======================初次登入成功，請填寫會員基本資料");
			
			return 2;
			
		}	
	}
	
}
