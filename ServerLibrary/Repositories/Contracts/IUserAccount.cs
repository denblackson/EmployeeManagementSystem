using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ServerLibrary.Repositories.Contracts
{
    public interface IUserAccount
    {
        Task<GeneralResponse> Create(Register user);
        Task<LoginResponse> SignIn(Login user);
        Task<LoginResponse> RefreshToken(RefreshToken token);
    }
}
