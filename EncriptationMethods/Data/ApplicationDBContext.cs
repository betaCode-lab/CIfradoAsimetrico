using EncriptationMethods.Models;
using Microsoft.EntityFrameworkCore;

namespace EncriptationMethods.Data
{
    public class ApplicationDBContext : DbContext
    {
        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
