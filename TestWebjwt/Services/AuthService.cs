using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NuGet.Common;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestWebjwt.Helpers;
using TestWebjwt.Models;

namespace TestWebjwt.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _usermanager;
        private readonly RoleManager<IdentityRole> _rolemanager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> usermanager, IOptions<JWT> jwt, RoleManager<IdentityRole> rolemanager)
        {
            _usermanager = usermanager;
            _jwt = jwt.Value;
            _rolemanager = rolemanager;
        }



        public async Task<AuthModel> Register(RegisterModel model)
        {
           if(await _usermanager.FindByEmailAsync(model.Email) is not null
            ||await _usermanager.FindByNameAsync(model.UserName) is not null)
                {
                return new AuthModel{ Messege = "Email already regisreed!" };
                }

            var user = new ApplicationUser
            {
                UserName=model.UserName,
                Email=model.Email,
                FirstName=model.FirstName,
                LastName=model.LastName,
            };
            var result= await _usermanager.CreateAsync(user,model.Password);
            if(!result.Succeeded)
            {
                var errors = string.Empty;
                foreach(var error in result.Errors)
                {
                    errors += $"{error.Description}, ";
                }
                return new AuthModel { Messege=errors};
            }
            await _usermanager.AddToRoleAsync(user, "User");
            var JwtSecurityToken = await createJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = JwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token=new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken),
                UserName= user.UserName,
            };
        }

        public async Task<AuthModel> GetToken(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user=await _usermanager.FindByEmailAsync(model.Email);
            if (user == null|| !await _usermanager.CheckPasswordAsync(user,model.Password))
            {
                authModel.Messege = "Email Or Password Is InCorrect !!!";
                return authModel;
            }
            var JwtSecurityToken = await createJwtToken(user);

            authModel.Email = user.Email;
            authModel.ExpiresOn = JwtSecurityToken.ValidTo;
            authModel.IsAuthenticated = true;
            authModel.Roles = (await _usermanager.GetRolesAsync(user)).ToList();
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken);
            authModel.UserName = user.UserName;

            return authModel;
        }

        public async Task<string> AddRole(AddRoleModel model)
        {
            var user = await _usermanager.FindByIdAsync(model.UserId); 
            
            if (user == null|| !await _rolemanager.RoleExistsAsync(model.Role))
                return "Invalid User Id OR Role";

            if (await _usermanager.IsInRoleAsync(user, model.Role))
                return "User Already assigned to this role";

            var result=await _usermanager.AddToRoleAsync(user, model.Role);

            return (result.Succeeded) ? string.Empty : "Something Went Wrong";
            
        }
        private async Task<JwtSecurityToken> createJwtToken(ApplicationUser user)
        {
           var userClaims=await _usermanager.GetClaimsAsync(user);
           var roles=await _usermanager.GetRolesAsync(user);
            var roleClaiims=new List<Claim>();

            foreach (var role in roles)
            {
                roleClaiims.Add(new Claim("roles", role));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim("uid",user.Id)

            }.Union(userClaims)
             .Union(roleClaiims);
            var SymmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            SigningCredentials SigningCredentials =
                new SigningCredentials(SymmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken mytoken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience, 
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: SigningCredentials
                );
            return mytoken;
        }

       
    }
}
