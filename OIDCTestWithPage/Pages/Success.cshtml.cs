using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OIDCTestWithPage.Pages
{
    [Authorize]
    public class SuccessModel : PageModel
    {

        public void OnGet()
        {
        }
    }
}
