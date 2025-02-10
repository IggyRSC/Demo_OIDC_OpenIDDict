using System.Diagnostics;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace OIDCTestWithPage.Pages
{

    [Authorize]
    public class Error : PageModel
    {
        [BindProperty]
        public string? ReturnUrl { get; set; }
        public string RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        private readonly ILogger<Error> _logger;

        public Error(ILogger<Error> logger)
        {
            _logger = logger;
        }

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
            return Page();
        }


    }

}
