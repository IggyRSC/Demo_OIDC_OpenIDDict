using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace OIDCTestWithPage.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
    }
}
