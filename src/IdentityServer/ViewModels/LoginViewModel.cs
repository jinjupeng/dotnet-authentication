﻿using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]//必须的
        [DataType(DataType.Password)]//内容检查是否为密码
        public string Password { get; set; }
    }
}
