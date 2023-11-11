using EncriptationMethods.Data;
using EncriptationMethods.Models;
using EncriptationMethods.Services.Contract;
using Microsoft.EntityFrameworkCore;

namespace EncriptationMethods.Services.Implementation
{
    public class UserService : IUserService
    {

        private readonly ApplicationDBContext _dbContext;

        public UserService(ApplicationDBContext dBContext)
        {
            _dbContext = dBContext;
        }

        public async Task<User> GetUserByEmail(string email)
        {
            User user = await _dbContext.Users.Where(u => u.Email == email).FirstOrDefaultAsync();

            return user;
        }

        public async Task<User> GetUser(string email, string password)
        {
            User user = await _dbContext.Users.Where(u => u.Email == email && u.Password == password).FirstOrDefaultAsync();

            return user;
        }

        public async Task<User> SaveUser(User user)
        {
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            return user;
        }
    }
}
