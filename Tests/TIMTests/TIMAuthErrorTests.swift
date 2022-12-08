import XCTest
import AppAuth
@testable import TIM

class TimErrorTests: XCTestCase {
    
    func testIsSafariViewControllerCancelled(){
        XCTAssertFalse(TIMAuthError.failedToBeginAuth.isSafariViewControllerCancelled())
        XCTAssertFalse(TIMAuthError.appAuthFailed(nil).isSafariViewControllerCancelled())
        XCTAssertFalse(TIMAuthError.authStateNil().isSafariViewControllerCancelled())
        XCTAssertFalse(TIMAuthError.failedToValidateIDToken.isSafariViewControllerCancelled())
        XCTAssertFalse(TIMAuthError.refreshTokenExpired.isSafariViewControllerCancelled())
        
        XCTAssertTrue(TIMAuthError.safariViewControllerCancelled.isSafariViewControllerCancelled())
    }
    
    func testMapAppAuthErrorNil(){
        let error = TIMAuthError.mapAppAuthError(nil)
        error.assertAppAuthFailed(expectedError: nil)
    }
    
    func testMapAppAuthErrorRegularNSError(){
        let innerAuthError = NSError(domain: "someDomain", code: 42)
        let error = TIMAuthError.mapAppAuthError(innerAuthError)
        error.assertAppAuthFailed(expectedError: innerAuthError)
    }
    
    func testMapAppAuthErrorOIDGeneralErrorDomainNetworkError() {
        let innerAuthError = NSError(
            domain: OIDGeneralErrorDomain,
            code: OIDErrorCode.networkError.rawValue
        )
        
        let error = TIMAuthError.mapAppAuthError(innerAuthError)
        error.assertNetworkError()
    }
    
    func testMapAppAuthErrorOIDGeneralErrorDomainIdTokenError() {
        let innerAuthError = NSError(
            domain: OIDGeneralErrorDomain,
            code: OIDErrorCode.idTokenFailedValidationError.rawValue
        )
        
        let error = TIMAuthError.mapAppAuthError(innerAuthError)
        error.assertFailedToValidateIDToken()
    }
    
    func testMapAppAuthErrorOIDGeneralErrorDomainUnknownErrorType(){
        let innerAuthError = NSError(
            domain: OIDGeneralErrorDomain,
            code: 999
        )
        
        let error = TIMAuthError.mapAppAuthError(innerAuthError)
        error.assertAppAuthFailed(expectedError: innerAuthError)
    }
    
    
    
}

extension TIMAuthError {
    func assertAppAuthFailed(expectedError: NSError?){
        if case TIMAuthError.appAuthFailed(let appAuthError) = self  {
            XCTAssertEqual(expectedError, appAuthError as? NSError)
        } else {
            XCTFailTest(message: "Expected an appAuthFailed but got \(self)")
        }
    }
    
    func assertNetworkError(){
        if case TIMAuthError.networkError = self  {
            
        } else {
            XCTFailTest(message: "Expected a networkError but got \(self)")
        }
    }

    func assertFailedToValidateIDToken(){
        if case TIMAuthError.failedToValidateIDToken = self  {
            
        } else {
            XCTFailTest(message: "Expected a failedToValidateIDToken but got \(self)")
        }
    }
}
