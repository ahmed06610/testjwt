using TestWebjwt.Models;

namespace TestWebjwt.Services
{
    public interface IAuthService
    {
        Task<AuthModel> Register(RegisterModel model);
        Task<AuthModel> GetToken(TokenRequestModel model);
        Task<String> AddRole(AddRoleModel model);
    }
}
