import AppAuth
import SafariServices

public class AuthSFController: OIDExternalUserAgentIOS, SFSafariViewControllerDelegate {
    private let presentingViewController: UIViewController
    private let shouldAnimateCallback: () -> Bool

    /// Called before presentation of the SFSafariViewController
    private let willPresentSafariViewController: (SFSafariViewController) -> Void

    /// User taps on cancel in SFSafariViewController
    private var didCancel: () -> Void

    public required init?(presentingViewController: UIViewController,
                          willPresentSafariViewControllerCallback: @escaping (SFSafariViewController) -> Void,
                          shouldAnimateCallback: @escaping () -> Bool,
                          didCancelCallback: @escaping () -> Void) {
        self.shouldAnimateCallback = shouldAnimateCallback
        self.willPresentSafariViewController = willPresentSafariViewControllerCallback
        self.presentingViewController = presentingViewController
        self.didCancel = didCancelCallback
        super.init(presenting: presentingViewController)
    }

    public override func present(_ request: OIDExternalUserAgentRequest, session: OIDExternalUserAgentSession) -> Bool {
        DispatchQueue.main.async {
            let safariViewController: SFSafariViewController = self.createSFViewController(request: request)
            self.willPresentSafariViewController(safariViewController)
            safariViewController.delegate = self
            self.presentingViewController.present(safariViewController, animated: self.shouldAnimateCallback())
        }
        return true
    }

    public override func dismiss(animated: Bool, completion: @escaping () -> Void) {
        presentingViewController.dismiss(animated: animated, completion: completion)
    }

    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        didCancel()
    }

    private func createSFViewController(request: OIDExternalUserAgentRequest) -> SFSafariViewController {
        let safariVC: SFSafariViewController
        if #available(iOS 11.0, *) {
            let config = SFSafariViewController.Configuration()
            config.barCollapsingEnabled = false
            config.entersReaderIfAvailable = false
            safariVC = SFSafariViewController(
                    url: request.externalUserAgentRequestURL(),
                    configuration: config)
            safariVC.dismissButtonStyle = .cancel
        } else {
            // Fallback on earlier versions
            safariVC = SFSafariViewController(
                    url: request.externalUserAgentRequestURL(),
                    entersReaderIfAvailable: false)
        }
        return safariVC
    }
}
