﻿using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ViewModels
{
    public class RegisterViewModel
    {
        [Required]//必须的
        [DataType(DataType.EmailAddress)]//内容检查是否为邮箱
        public string Email { get; set; }

        [Required]//必须的
        [DataType(DataType.Password)]//内容检查是否为密码
        public string Password { get; set; }

        [Required]//必须的
        [DataType(DataType.Password)]//内容检查是否为密码
        public string ConfirmedPassword { get; set; }
    }
}
