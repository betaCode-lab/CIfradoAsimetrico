using EncriptationMethods.Models;

namespace EncriptationMethods.Services.Contract
{
    public interface IUserService
    {
        Task<User> GetUserByEmail(string email);

        Task<User> GetUser(string email, string password);

        Task<User> SaveUser(User user);
    }
}
